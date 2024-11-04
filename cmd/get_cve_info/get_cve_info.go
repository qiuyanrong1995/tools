package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/antchfx/htmlquery"
)

var (
	cveIdsFlag []string
	fileFlag   string
	cveInfos   map[string]string
)

func main() {
	for _, cveId := range cveIdsFlag {
		desc := getCveInfoFromMap(cveId)
		if desc == "" {
			desc = translate(getCveInfoFromNvd(cveId))
			cveInfos[cveId] = desc
		}
		fmt.Printf("%s: %s\n", cveId, desc)
	}

	if fileFlag != "" {
		content, err := os.ReadFile(fileFlag)
		if err != nil {
			fmt.Printf("Failed to read file, filePath=%s\n", fileFlag)
			os.Exit(-1)
		}
		for _, cveId := range strings.Split(string(content), "\n") {
			if cveId == "" {
				continue
			}

			isCVE, err := checkCveId(cveId)
			if err != nil {
				fmt.Printf("Failed to parse CVE ID. err=%s\n", err)

			}
			if isCVE {
				desc := getCveInfoFromMap(cveId)
				if desc == "" {
					desc = translate(getCveInfoFromNvd(cveId))
					cveInfos[cveId] = desc
				}
				fmt.Printf("%s: %s\n", cveId, desc)
			} else {
				fmt.Printf("Invalid CVE ID. cveId=%s\n", cveId)
			}
		}
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  -f string\n")
	fmt.Fprintf(os.Stderr, "     CVE ID list of file, split by '\\n'.\n")
	fmt.Fprintf(os.Stderr, "  [CVE ID1] [CVE ID2]\n")
	fmt.Fprintf(os.Stderr, "     specified CVE ID list.\n")
}

func init() {
	cveInfos = make(map[string]string)
	flag.Usage = usage
	flag.StringVar(&fileFlag, "f", "", "")
	flag.Parse()

	for _, arg := range flag.Args() {
		isCVE, err := checkCveId(arg)
		if err != nil {
			fmt.Printf("Failed to parse CVE ID. err=%s\n", err)
			os.Exit(-1)
		}
		if isCVE {
			cveIdsFlag = append(cveIdsFlag, arg)
		} else {
			fmt.Printf("Invalid CVE ID. arg=%s\n", arg)
			os.Exit(-1)
		}
	}
}

func checkCveId(s string) (bool, error) {
	res, err := regexp.MatchString("CVE-\\d+-\\d+", s)
	return res, err
}

func getCveInfoFromNvd(cveId string) string {
	resp, err := http.Get("https://nvd.nist.gov/vuln/detail/" + strings.ToLower(cveId))
	if err != nil {
		fmt.Printf("Failed to obtain cve info, err=%s\n", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Invalid http status. status=%s\n", resp.Status)
		return ""
	}

	html, err := htmlquery.Parse(resp.Body)
	if err != nil {
		fmt.Printf("Failed to parse html. err=%s\n", err)
		return ""
	}
	node, err := htmlquery.Query(html, `//*[@id="vulnDetailTableView"]/tbody/tr/td/div/div[1]/p`)
	if err != nil {
		fmt.Printf("Failed to query xpath. err=%s\n", err)
		return ""
	}

	return htmlquery.InnerText(node)
}

func getCveInfoFromMap(cveId string) string {
	res, ok := cveInfos[cveId]
	if ok {
		return res
	} else {
		return ""
	}
}

func sha256hex(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}

func hmacsha256(s, key string) string {
	hashed := hmac.New(sha256.New, []byte(key))
	hashed.Write([]byte(s))
	return string(hashed.Sum(nil))
}

func translate(desc string) string {
	secretId := "AKIDPchaZbZRKD0hEaqvseHpCO**********"
	secretKey := "oY7Tdgw76nPr7BHHKE2kMp**********"
	host := "tmt.tencentcloudapi.com"
	algorithm := "TC3-HMAC-SHA256"
	service := "tmt"
	version := "2018-03-21"
	action := "TextTranslate"
	region := "ap-beijing"
	var timestamp int64 = time.Now().Unix()

	// step 1: build canonical request string
	httpRequestMethod := "POST"
	canonicalURI := "/"
	canonicalQueryString := ""
	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-tc-action:%s\n",
		"application/json; charset=utf-8", host, strings.ToLower(action))
	signedHeaders := "content-type;host;x-tc-action"

	data := map[string]any{
		"SourceText": desc,
		"Source":     "en",
		"Target":     "zh",
		"ProjectId":  0,
	}
	payload, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Failed to marshal data, err=%s\n", err)
		return ""
	}
	hashedRequestPayload := sha256hex(string(payload))
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		httpRequestMethod,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		hashedRequestPayload)

	// step 2: build string to sign
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	credentialScope := fmt.Sprintf("%s/%s/tc3_request", date, service)
	hashedCanonicalRequest := sha256hex(canonicalRequest)
	string2sign := fmt.Sprintf("%s\n%d\n%s\n%s",
		algorithm,
		timestamp,
		credentialScope,
		hashedCanonicalRequest)

	// step 3: sign string
	secretDate := hmacsha256(date, "TC3"+secretKey)
	secretService := hmacsha256(service, secretDate)
	secretSigning := hmacsha256("tc3_request", secretService)
	signature := hex.EncodeToString([]byte(hmacsha256(string2sign, secretSigning)))

	// step 4: build authorization
	authorization := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm,
		secretId,
		credentialScope,
		signedHeaders,
		signature)

	req, err := http.NewRequest(httpRequestMethod, "https://"+host, bytes.NewBuffer(payload))
	if err != nil {
		fmt.Printf("Failed to build http request, err=%s\n", err)
		return ""
	}

	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Timestamp", strconv.Itoa(int(timestamp)))
	req.Header.Set("X-TC-Version", version)
	req.Header.Set("X-TC-Region", region)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Failed to do request, err=%s\n", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Invalid http response status code, status_code=%d\n", resp.StatusCode)
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read body, err=%s\n", err)
		return ""
	}

	r := struct {
		Response struct {
			TargetText string `json:"TargetText"`
		} `json:"Response"`
	}{}

	err = json.Unmarshal(body, &r)
	if err != nil {
		fmt.Printf("Failed to unmarshal response data, err=%s\n", err)
		return ""
	}

	return r.Response.TargetText
}

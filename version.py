import re
from typing import Literal


class Version:
    nums: list[int] = []
    tag: str = ""
    tag_num: int = 0
    tag_pool: dict[str, int] = {
        "snapshot": 0,
        "alpha": 1,
        "beta": 2,
        "m": 3,
        "cr": 4,
        "rc": 4,
        "mr": 5,
        "ga": 5,
        "final": 5,
        "release": 5,
        "": 6,
    }

    def __init__(self, version: str):
        parts = re.split(r"[\.-]", version)
        for idx, part in enumerate(parts):
            if idx == len(parts) - 1 and not part.isdigit():
                part = part.lower()
                groups = re.findall(r"\d+", part)
                if groups:
                    tag_num = groups.pop()
                    self.tag_num = int(tag_num)
                    part = part.replace(tag_num, "")
                self.tag = part
            else:
                self.nums.append(int(part))

    def compare(self, version2: "Version") -> Literal[1, 0, -1]:
        # 比较数字部分
        max_len = max(len(self.nums), len(version2.nums))
        for i in range(max_len):
            num1 = self.nums[i] if i < len(self.nums) else 0
            num2 = version2.nums[i] if i < len(version2.nums) else 0
            if num1 != num2:
                return 1 if num1 > num2 else -1

        # 比较常规的版本标识
        weight1 = self.tag_pool.get(self.tag, 7)
        weight2 = self.tag_pool.get(version2.tag, 7)
        if weight1 != weight2:
            return 1 if weight1 > weight2 else -1

        # 比较特殊的版本标识
        if weight1 == 7 and self.tag != version2.tag:
            raise ValueError(
                "两个版本存在特殊 tag 无法比较, version1.tag: %s, version2.tag: %s"
                % (self.tag, version2.tag)
            )

        # 比较版本标识的数字部分
        if self.tag_num != version2.tag_num:
            return 1 if self.tag_num > version2.tag_num else -1

        return 0


if __name__ == "__main__":
    version1 = Version("1.10.100.1000.sec1")
    version2 = Version("1.10.100.1000.sec1")

    print(version1.compare(version2))

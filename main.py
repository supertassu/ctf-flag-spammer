from argparse import ArgumentParser
import logging
import os.path
import requests
import yaml


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.captureWarnings(True)

logger = logging.getLogger("ctf-flag-spammer")
logger.setLevel(logging.DEBUG)


class CtfFlagSpammer:
    def __init__(self, config: dict, flags: dict):
        self.config = config
        self.flags = flags
        self.requests = requests.Session()
        self.base_url = config["CTFD"]["URL"]
        self.fails_file = config["FAILED_FILE"]
        self.fails = []

        if os.path.exists(self.fails_file):
            self.fails = yaml.safe_load(open(self.fails_file, "r"))

    def _request_headers(self):
        return {
            "Authorization": "Token " + self.config["CTFD"]["TOKEN"],
            "Content-Type": "application/json",
            "User-Agent": self.config["USER_AGENT"],
        }

    def normalise_chall_name(self, chall_obj):
        return (chall_obj["category"] + " " + chall_obj["name"]).lower()

    def exec(self, count=None):
        challs_response = self.requests.get(
            self.base_url + "/api/v1/challenges", headers=self._request_headers()
        )
        challs_response.raise_for_status()

        if count is not None and count == len(challs_response.json()["data"]):
            logger.info("Did not found any new challenges")
            return

        solves_response = self.requests.get(
            self.base_url + "/api/v1/users/me/solves", headers=self._request_headers()
        )
        solves_response.raise_for_status()

        solved = []
        for solve in solves_response.json()["data"]:
            solved.append(self.normalise_chall_name(solve["challenge"]))
        logger.info(
            "Found %s solves for %s challenges",
            len(solved),
            len(challs_response.json()["data"]),
        )

        tryagain = False

        for chall in challs_response.json()["data"]:
            chall_name = self.normalise_chall_name(chall)
            if chall_name in self.fails:
                continue
            if chall_name in solved:
                continue
            result = self.try_solve(chall, chall_name)

            if result:
                tryagain = True

        if tryagain:
            logger.info("Checking if any more challenges were unlocked")
            self.exec(len(challs_response.json()["data"]))

    def try_solve(self, chall, chall_name):
        for possible in self.flags:
            # loops two layers deep, can't break
            matched = True
            for keyword in possible["match"]:
                if str(keyword) not in chall_name:
                    matched = False
                    break
                logger.debug("Keyword %s matched part of name %s", keyword, chall_name)
            if not matched:
                continue

            logger.info(
                "Attempting to submit flag %s to challenge %s",
                possible["flag"],
                chall_name,
            )
            submission_response = self.requests.post(
                self.base_url + "/api/v1/challenges/attempt",
                json={"challenge_id": chall["id"], "submission": possible["flag"]},
                headers=self._request_headers(),
            )
            ok = submission_response.json()["data"]["status"] == "correct"

            try:
                requests.post(
                    self.config["DISCORD_HOOK"]["URL"],
                    json={
                        "content": self.config["DISCORD_HOOK"]["PING"]
                        + ": "
                        + ("solved" if ok else "**failed**")
                        + " "
                        + chall_name,
                        "username": "ctf-flag-spammer",
                    },
                )
            except:
                logger.exception("Failed to send Discord notification")

            if ok:
                logger.info("Flag submitted successfully")
                return True
            else:
                logger.warning(
                    "failed to submit flag; %s %s",
                    submission_response.status_code,
                    submission_response.text,
                )
                self.fails.append(chall_name)

                try:
                    if len(self.fails_file) > 0:
                        with open(self.fails_file, "w") as f:
                            f.write(yaml.safe_dump(self.fails))
                except:
                    logger.exception("Failed to write fail file")
            return False
        logger.info("Did not find a flag for %s", chall_name)
        return False


def main():
    parser = ArgumentParser(description="ctf-flag-spammer")
    parser.add_argument(
        "-c",
        "--config",
        default=os.path.join(os.path.dirname(__file__), "config.yaml"),
        help="Configuration file",
    )
    parser.add_argument(
        "-f",
        "--flags",
        default=os.path.join(os.path.dirname(__file__), "flags.yaml"),
        help="Flag config file",
    )

    args = parser.parse_args()
    config = yaml.safe_load(open(args.config, "r"))
    flags = yaml.safe_load(open(args.flags, "r"))["flags"]

    spammer = CtfFlagSpammer(config, flags)
    spammer.exec()


if __name__ == "__main__":
    main()

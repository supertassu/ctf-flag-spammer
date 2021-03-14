from argparse import ArgumentParser
import os.path
import requests
import yaml


class CtfFlagSpammer():
    def __init__(self, config: dict, flags: dict):
        self.config = config
        self.flags = flags
        self.requests = requests.Session()
        self.base_url = config['CTFD']['URL']
        self.fails_file = config['FAILED_FILE']
        self.fails = []

        if os.path.exists(self.fails_file):
            self.fails = yaml.safe_load(open(self.fails_file, "r"))

    def _request_headers(self):
        return {
            "Authorization": "Token " + config['CTFD']['TOKEN'],
            "Content-Type": "application/json",
            "User-Agent": "taavi's auto submit bot, please ping taavi#0036 if it's causing problems"
        }

    def normalise_chall_name(self, chall_obj):
        return (chall_obj['category'] + ' ' + chall_obj['name']).lower()

    def exec(self):
        solves_response = self.requests.get(self.base_url + "/api/v1/users/me/solves", headers=self._request_headers())
        solved = []
        for solve in solves_response.json()['data']:
            solved.append(self.normalise_chall_name(solve['challenge']))

        challs_response = self.requests.get(self.base_url + "/api/v1/challenges", headers=self._request_headers())
        print('Found', len(solved), 'solves for', len(challs_response.json()['data']), 'challenges')
        for chall in challs_response.json()['data']:
            chall_name = self.normalise_chall_name(chall)
            if chall_name in self.fails:
                continue
            if chall_name in solved:
                continue
            self.try_solve(chall, chall_name)

    def try_solve(self, chall, chall_name):
        for possible in self.flags:
            # loops two layers deep, can't break
            matched = True
            for keyword in possible['match']:
                if keyword not in chall_name:
                    matched = False
                    break
                print('Keyword', keyword, 'matched part of name', chall_name)
            if not matched:
                continue

            print("Attempting to submit flag", possible['flag'], "to challenge", chall_name, chall['id'])
            submission_response = self.requests.post(self.base_url + "/api/v1/challenges/attempt",
                                                     json={
                                                         "challenge_id": chall['id'],
                                                         "submission": possible['flag']
                                                     },
                                                     headers=self._request_headers())
            ok = submission_response.json()['data']['status'] == 'correct'
            if ok:
                print("OK")
            else:
                print('failed', submission_response.status_code, submission_response.text)
                self.fails.append(chall_name)

                if len(self.fails_file) > 0:
                    with open(self.fails_file, 'w') as f:
                        f.write(yaml.safe_dump(self.fails))

            requests.post(self.config['DISCORD_HOOK']['URL'], json={
                "content": self.config['DISCORD_HOOK']['PING'] + ': ' + ('solved' if ok else '**failed**') + ' ' + chall_name,
                "username": 'ctf-flag-spammer'
            })
            break
        print('Did not find a flag for', chall_name)


if __name__ == '__main__':
    parser = ArgumentParser(description="ctf-flag-spammer")
    parser.add_argument("-c", "--config",
                        default=os.path.join(os.path.dirname(__file__), 'config.yaml'),
                        help="Configuration file")
    parser.add_argument("-f", "--flags",
                        default=os.path.join(os.path.dirname(__file__), 'flags.yaml'),
                        help="Flag config file")

    args = parser.parse_args()
    config = yaml.safe_load(open(args.config, "r"))
    flags = yaml.safe_load(open(args.flags, "r"))['flags']

    spammer = CtfFlagSpammer(config, flags)
    spammer.exec()

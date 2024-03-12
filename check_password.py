import requests
import hashlib
import sys

API_URL = 'https://api.pwnedpasswords.com/range/'


def request_api_data(query_chars):
    url = API_URL + query_chars
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check API and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    for line in hashes.text.splitlines():
        h, count = line.split(':')
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(passwords):
    sha1_passwords = [hashlib.sha1(password.encode('utf-8')).hexdigest().upper() for password in passwords]
    first5_chars = [sha1[:5] for sha1 in sha1_passwords]
    response = request_api_data(','.join(first5_chars))
    return [get_password_leaks_count(response, sha1[5:]) for sha1 in sha1_passwords]


def main(args):
    counts = pwned_api_check(args)
    for password, count in zip(args, counts):
        if count:
            print(f'{password} was found {count} times.. change password')
        else:
            print(f'{password} was not found, all good!')
    return 'done'


if __name__ == "__main__":
    main(sys.argv[1:])

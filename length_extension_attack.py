#!/usr/bin/python3
import argparse
import codecs
import logging
import math
import os
import sys
import urllib
from pymd5 import LOG_DIVIDER
from pymd5 import MD5

BITS_IN_BYTES = 8


class LengthExtAttack:
    def __init__(self, args):
        log_level = logging.DEBUG if args.verbose else logging.INFO
        logging.basicConfig(level=log_level, format=("[%(levelname)s Message] %(message)s"))
        self.logger = logging.getLogger(__file__)
        self.mal_add = None

    def get_padding(self, length_in_bytes):
        hex_value = hex(length_in_bytes * BITS_IN_BYTES)[2:]
        if len(hex_value) % 2 == 1:
            hex_value = "0" + hex_value
        # "[::-1]" ==> Length field is little-endian, so we need to reverse the order of bytes here
        length_field = codecs.decode(hex_value, "hex")[::-1]
        num_nulls = 8 - len(length_field)

        # To understand why the padding is constructed this way, please see the "Padding" section of this
        # writeup: https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
        return b"\x80" + (55 - length_in_bytes) * b"\0" + length_field + (num_nulls * b"\0")

    def craft_malicious_md5(self, orig_msg, hash_orig_md5):
        attack_md5 = MD5("", logger=self.logger)
        # To be honest, I don't know why self.get_padding(0) works below :shame:
        attack_md5.update(self.get_padding(0) + self.mal_add)
        attack_md5.set_state(hash_orig_md5)
        hash_attack_md5 = attack_md5.hexdigest()

        self.logger.info(
            "\n###########################"
            "\n# Length Extension Attack #"
            "\n###########################\n"
            "\nMD5_Length_Extension(malicious_addition) => {}"
            "\nMalicious Message => {}"
            "\n{}".format(hash_attack_md5, orig_msg + self.get_padding(0) + self.mal_add, LOG_DIVIDER)
        )
        return hash_attack_md5

    def run(self, orig_msg, malicious_addition, secret_prefix):
        if len(malicious_addition) > MD5.block_size - 1:
            self.logger.error(
                "Abort the program as it does Not work with a "
                "--malicious_addition that is longer than {} bytes".format(MD5.block_size - 1)
            )
            return
        self.mal_add = malicious_addition

        padding = self.get_padding(len(secret_prefix) + len(orig_msg))
        self.logger.info(
            "\n######################"
            "\n# Program Parameters #"
            "\n######################\n"
            "\nsecret_prefix => {}"
            "\norig_msg => {}"
            "\nmalicious_addition => {}"
            "\npadding => {}\n{}".format(secret_prefix, orig_msg, self.mal_add, padding, LOG_DIVIDER)
        )

        # Original Message normal MD5 computation
        orig_md5 = MD5(secret_prefix + orig_msg)
        hash_orig_md5 = orig_md5.hexdigest()

        # Regular MD5 computation of the malicious message, by using the secret_prefix
        mal_md5 = MD5(secret_prefix + orig_msg + padding + self.mal_add)
        normal_malicious_md5 = mal_md5.hexdigest()

        self.logger.info(
            "\n#################################"
            "\n# Regular MD5 Hash Computations #"
            "\n#################################\n"
            "\nMD5(secret_prefix + orig_msg) => {}"
            "\nMD5(secret_prefix + orig_msg + malicious_addition) => {}"
            "\n{}".format(hash_orig_md5, normal_malicious_md5, LOG_DIVIDER)
        )

        # MD5 Length Extension Attack
        # Generate the MD5 value for the malicious message without using the secret_prefix.
        length_extension_attack_md5 = self.craft_malicious_md5(orig_msg, hash_orig_md5)
        if normal_malicious_md5 == length_extension_attack_md5:
            self.logger.info(
                "Success!\n\nMD5(secret_prefix + orig_msg + malicious_addition) == "
                "MD5_Length_Extension(malicious_addition)"
            )
        else:
            raise RuntimeError("Failure: {} != {}".format(normal_malicious_md5, length_extension_attack_md5))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--secret_prefix",
        default="secret",
        help="A secret that a server will prepend to an arriving message (see the `original_message` "
        'arg) before generating an MD5 hash that is used to subsequently "validate" this same '
        'message (default => "%(default)s").',
    )
    parser.add_argument(
        "-o",
        "--original_message",
        default="data",
        help="A user-controlled message that is sent to the server, which the server prepends a "
        "secret to (see the `--secret` arg) before generating an MD5 hash that is often sent back "
        'to the user (default => "%(default)s").',
    )
    parser.add_argument(
        "-m",
        "--malicious_addition",
        default="append",
        help="Additional content that an attacker wishes to append to the the original message, and "
        'then generate a valid MD5 hash for without knowing the server secret (default => "%(default)s").',
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Increases the logging level of the program from INFO to DEBUG."
    )
    return parser.parse_args()


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    args = parse_args()

    LengthExtAttack(args).run(
        bytes(args.original_message, "utf-8"),
        bytes(args.malicious_addition, "utf-8"),
        bytes(args.secret_prefix, "utf-8"),
    )


if __name__ == "__main__":
    main()

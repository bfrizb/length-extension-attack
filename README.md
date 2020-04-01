# Length Extension Attack

## Purpose

To enable others to more easily experiment with [length extension attacks](https://en.wikipedia.org/wiki/Length_extension_attack).

### tl;dr purpose

When I was reading up on length extension attacks, I went looking for code I could play around with to better understand how they work. I found this [excellent technical writeup](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) detailing the attack, but the example code is in written CLang, which isn't as easily to quickly experiment with as an interpreted language such as python. Additionally, I found an [existing repo](https://github.com/cbornstein/python-length-extension/blob/master/len_ext.py) with python code for a length extension attack, but I did not find it malleable as I would've liked. The code in this repository borrows heavily from these two other resources, and I thank those authors for their work.

## Usage

For program usage and help: `$ python length_extension_attack.py -h`

## Explanation

I recommend [this skullsecurity blog post](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) for a detailed technical explanation of how length extension attacks work. Note that the default values used by the `length_extension_attack.py` script in this repository are identical to those used in that blog post.

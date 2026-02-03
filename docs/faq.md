## Why is it called the Domain API
We used the term domain to illustrate that the objective is to expose reversing engineering concepts as first level entry point to the API.
When looking at the docs the first time, the user should easily be able to understand the structure of the API and implement what he wants to do.

## If I use the Domain API, can I still use the IDA Python SDK?
Absolutely. Both can be used together. This was a requirement at the start to make sure we can build the Domain API iteratively.

## Why didn’t you put all this in the ida_utils package
Our first goal was to decouple the IDA Domain API from the SDK itself to be able to iterate faster.
Also, having it as a standalone package allows us to publish it independently and have a specific versioning cycle.

## Is the IDA Domain API published on PyPi
Yes, the IDA Domain API is available directly using `pip install ida-domain` and setting `IDADIR` environment variable.
See our [documentation](getting_started.md) how to get started.

## Why is the IDA Domain API only in Python?
As this is the start of a journey, we first want to validate our approach and make sure the IDA Domain API reaches a certain level of maturity before porting it to C.
The goal is also to push down specific behaviours or simplifications to the IDA SDK itself.

## Can I use IDA Domain in my plugin?
Yes, the IDA Domain package can be used transparently inside or outside of IDA. And can also be used alongside the current IDA Python SDK.
When used inside IDA, you can only work with the currently opened IDB.

## What happens when the Domain API is updated?
It’s independently versioned. You can pin a version for stability.

## Is this meant to replace the IDA Python SDK?
No, it’s a complement to simplify scripting.

## Can I contribute?
Yes! It’s open source and contributions are welcome.

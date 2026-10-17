import asyncio
import json
import business

assert __name__ == "__main__"
print(json.dumps(asyncio.run(business.root()), sort_keys=True))

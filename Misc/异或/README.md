# 异或

## 题面

*by Nemo.*

他说，`Prometheus was punished by the gods for giving the gift of knowledge to man. He was cast into the bowels of the earth and pecked by birds.`

他说，`b'3\x13\x1b\x0e\x11\x12\x13\x1d:\x01\x7f\x14!=\x7f\x1201\x1b\x16\x1eF6sA=]'`

他说，异或。

## WP

搜索和编写脚本的能力

1. 查找得知异或是一种操作，理想的情况下应该能找到一些示例。
2. 研读示例。
3. 观察到题面中给的是 `b''`，通过搜索大概知道这个是 Python 的 bytes 格式。
4. 使用 Python 或者别的语言得到答案。

## 源码

```python
import logging
from itertools import cycle

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s.%(funcName)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def xor_strings(s, t) -> bytes:
    """Concate xor two strings together."""
    if isinstance(s, str):
        s = s.encode('utf8')
    if isinstance(t, str):
        t = t.encode('utf8')
    if not isinstance(s, bytes) or not isinstance(t, bytes):
        raise TypeError('Both arguments must be bytes or bytes-encodable str.')
    # Bytes objects contain integer values in the range 0-255
    return bytes([a ^ b for a, b in zip(s, cycle(t))])


message = 'catctf{xOr_c@N_bE_rev#RS#D}'
logger.info(f'Message: {message}')

key = 'Prometheus was punished by the gods for giving the gift of knowledge to man. He was cast into the bowels of the earth and pecked by birds.'
logger.info(f'Key: {key}')

cipherText = xor_strings(message, key)
logger.info(f'cipherText: {cipherText}')
decrypted = xor_strings(cipherText, key).decode('utf8')
logger.info(f'decrypted: {decrypted}')

# Verify
if decrypted == message:
    logger.info('Unit test passed')
else:
    logger.fatal('Unit test failed')

print(xor_strings(b'3\x13\x1b\x0e\x11\x12\x13\x1d:\x01\x7f\x14!=\x7f\x1201\x1b\x16\x1eF6sA=]', key))```
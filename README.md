aws_session_handler
===================

Amazon Web Service python session helper


Features
--------
* cache credentials on disk if assume_role with mfa serial

Usage
-----
```bash
pip install aws-session-handler
```
```python
from aws_session_handler import AwsSessionHandler

handler = AwsSessionHandler(profile='default')
s3 = handler.client('s3')
print(s3.list_buckets())

```

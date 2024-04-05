import os
import json
import boto3

from botocore import session
from datetime import datetime, timezone, timedelta


class AwsSessionHandler:
    def __init__(self, profile='default',
                 region=None,
                 cache_file=None,
                 disable_file_cache=False,
                 long_session_duration=None,
                 short_session_duration=None
                 ):
        """
        Create session handler (automaticly detects if assume role is nessessary and cache's mfa session)

        :param region: aws region (lookup from aws credentials config or override)
        :param profile: aws profile (from aws-cli credential and config file)
        :param cache_file: cache file location
        (defaults os.path.join('~', '.aws', 'app', 'cache', 'AwsSessionHandler.json'))
        :param disable_file_cache: disable credentials disk cache (default False)
        :param long_session_duration: how long to cache the long session (defaults 12h)
        :param short_session_duration: how long to cache the short session (defaults 15m
        """
        self._profile = profile
        self._region = region
        self._config = None
        self._lookup_session = None
        self._config_lookup()

        self._session = None
        self._disk_cache_disable = disable_file_cache
        self._long_session_token = None
        self._long_session_duration = long_session_duration if long_session_duration else 43200  # => 12u
        self._short_session_token = None
        self._short_session_duration = short_session_duration if short_session_duration else 900  # => 15

        if not self._disk_cache_disable:
            if cache_file:
                dirname = os.path.dirname(cache_file)
                if not os.path.exists(dirname):
                    raise Exception("Directory dos not exists: {}".format(dirname))

                if not os.access(dirname, os.W_OK):
                    raise Exception("Directory not readable {}".format(dirname))

                if os.path.exists(cache_file) and not os.access(cache_file, os.W_OK):
                    raise Exception("CacheFile is not writable {}".format(cache_file))

                self._cache_file = cache_file
            else:
                # There must be a better way for resolving aws cache path
                cache_filename = 'AwsSessionHandler.json'
                cache_dir = os.path.expanduser(os.path.join('~', '.aws', 'app', 'cache'))
                os.makedirs(cache_dir, mode=0o775, exist_ok=True)

                self._cache_file = os.path.join(cache_dir, cache_filename)

            # preload cache tokens if exists
            if os.path.exists(self._cache_file) and os.access(self._cache_file, os.W_OK):
                with open(self._cache_file, 'r') as f:
                    cache_tokens = json.load(f)

                if 'long_session_token' in cache_tokens:
                    self._long_session_token = cache_tokens['long_session_token']

                if 'short_session_token' in cache_tokens:
                    self._short_session_token = cache_tokens['short_session_token']

    def set(self, profile=None, region=None):
        """
        set/change profile and region
        :param profile:
        :param region:
        """
        if profile:
            self._profile = profile
        if region:
            self._region = region

    def client(self, *args, **kwargs):
        """
        Lookup credentials and give a boto3 client in return
        (check boto3 client for args, kwargs)
        :param args:
        :param kwargs:
        :return: boto3 session client
        """
        if not self._profile and not self._region:
            raise Exception('ERROR: missing region and profile (use self.set(profile_name=None, region=None)')

        self._get_session()
        return self._session.client(*args, **kwargs)

    def resource(self, *args, **kwargs):
        """
        Lookup credentials and give a boto3 resource in return
        (check boto3 client for args, kwargs)
        :param args:
        :param kwargs:
        :return: boto3 session client
        """
        if not self._profile and not self._region:
            raise Exception('ERROR: missing region and profile (use self.set(profile_name=None, region=None)')

        self._get_session()
        return self._session.resource(*args, **kwargs)

    def get_session(self):
        self._get_session()
        return self._session

    def _config_lookup(self):
        self._lookup_session = session.get_session()
        self._lookup_session.set_config_variable('profile', self._profile)
        # lookup_session.set_config_variable('region', self._region)
        self._config = self._lookup_session.get_scoped_config()

        if 'region' in self._config and not self._region:
            self._region = self._config['region']

    def _get_session(self):
        self._config_lookup()
        # check if we need assuming a role and if mfa_serial is required
        # then we will create a long_token and an assume role(short_token)
        #
        if all(key in self._config for key in ('role_arn', 'mfa_serial', 'source_profile')):
            token_changed = False
            # now + 10 seconds (reserve expire time for assuming role)
            now = datetime.now(tz=timezone.utc) + timedelta(seconds=10)

            # Check if session tokens are valid
            if self._long_session_token:
                long_expire = datetime.strptime(''.join(self._long_session_token['expire'].rsplit(':', 1)),
                                                '%Y-%m-%dT%H:%M:%S%z')
                if long_expire <= now:
                    token_changed = True
                    self._long_session_token = None
                    self._short_session_token = None
                elif self._long_session_token['source_profile'] != self._config['source_profile']:
                    # we need to get a new long_token because source_profile switch
                    # the short token is no longer valid
                    self._long_session_token = None
                    self._short_session_token = None

            if self._short_session_token:
                short_expire = datetime.strptime(''.join(self._short_session_token['expire'].rsplit(':', 1)),
                                                 '%Y-%m-%dT%H:%M:%S%z')
                if short_expire <= now:
                    self._short_session_token = None
                elif self._short_session_token['profile'] != self._profile:
                    # We need to switch profile and remove cache
                    self._short_session_token = None

            if not self._long_session_token:
                tmp_session = boto3.Session(profile_name=self._config['source_profile'], region_name=self._region)
                tmp_sts = tmp_session.client('sts')
                token = str(input('MFA_Token: '))
                cred = tmp_sts.get_session_token(
                    DurationSeconds=self._long_session_duration,
                    SerialNumber=self._config['mfa_serial'],
                    TokenCode=token,
                )['Credentials']
                self._long_session_token = {
                    'aws_access_key_id': cred['AccessKeyId'],
                    'aws_secret_access_key': cred['SecretAccessKey'],
                    'aws_session_token': cred['SessionToken'],
                    'expire': cred['Expiration'].isoformat(),
                    'source_profile': self._config['source_profile'],
                    'region': self._region,
                }

            if not self._short_session_token:
                token_changed = True
                assume_session = boto3.Session(
                    aws_access_key_id=self._long_session_token['aws_access_key_id'],
                    aws_secret_access_key=self._long_session_token['aws_secret_access_key'],
                    aws_session_token=self._long_session_token['aws_session_token'],
                )
                tmp_sts = assume_session.client('sts')
                resp = tmp_sts.assume_role(
                    RoleArn=self._config['role_arn'],
                    RoleSessionName='SessionHandlerAssumeRole',
                    DurationSeconds=self._short_session_duration,
                )['Credentials']
                self._short_session_token = {
                    'aws_access_key_id': resp['AccessKeyId'],
                    'aws_secret_access_key': resp['SecretAccessKey'],
                    'aws_session_token': resp['SessionToken'],
                    'expire': resp['Expiration'].isoformat(),
                    'profile': self._profile,
                    'region': self._region,
                }

            # Get new session
            self._session = boto3.Session(
                region_name=self._region,
                aws_access_key_id=self._short_session_token['aws_access_key_id'],
                aws_secret_access_key=self._short_session_token['aws_secret_access_key'],
                aws_session_token=self._short_session_token['aws_session_token'],
            )

            # Write cache file if changed
            if token_changed:
                self._write_cache_file()

        # If no mfa_serial is needed, use boto3 default session handler
        else:
            self._session = boto3.Session(botocore_session=self._lookup_session)

    def _write_cache_file(self):
        if not self._disk_cache_disable:
            cache_tokens = {'long_session_token': self._long_session_token,
                            'short_session_token': self._short_session_token}

            with open(self._cache_file, 'w') as f:
                json.dump(cache_tokens, f)

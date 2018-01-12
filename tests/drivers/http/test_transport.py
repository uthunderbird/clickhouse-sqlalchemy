from base64 import b64encode
from datetime import date

from responses import mock
from sqlalchemy import Column, func, create_engine

from src import types, Table, make_session
from src.util import compat
from tests.session import session
from tests.testcase import BaseTestCase


class TransportCase(BaseTestCase):

    @mock.activate
    def test_parse_func_count(self):
        mock.add(
            mock.POST, 'http://localhost:8123', status=200,
            body='count_1\nUInt64\n42\n'
        )

        table = Table(
            't1', self.metadata(),
            Column('x', types.Int32, primary_key=True)
        )

        rv = session.query(func.count()).select_from(table).scalar()
        self.assertEqual(rv, 42)

    @mock.activate
    def test_parse_int_types(self):
        types_ = [
            'Int8', 'UInt8', 'Int16', 'UInt16', 'Int32', 'UInt32', 'Int64',
            'UInt64'
        ]
        columns = [chr(i + ord('a')) for i in range(len(types_))]

        mock.add(
            mock.POST, 'http://localhost:8123', status=200,
            body=(
                '\t'.join(columns) + '\n' +
                '\t'.join(types_) + '\n' +
                '\t'.join(['42'] * len(types_)) + '\n'
            )
        )

        table = Table(
            't1', self.metadata(),
            *[Column(col, types.Int) for col in columns]
        )

        rv = session.query(*table.c).first()
        self.assertEqual(rv, tuple([42] * len(columns)))

    @mock.activate
    def test_parse_float_types(self):
        types_ = ['Float32', 'Float64']
        columns = ['a', 'b']

        mock.add(
            mock.POST, 'http://localhost:8123', status=200,
            body=(
                '\t'.join(columns) + '\n' +
                '\t'.join(types_) + '\n' +
                '\t'.join(['42'] * len(types_)) + '\n'
            )
        )

        table = Table(
            't1', self.metadata(),
            *[Column(col, types.Float) for col in columns]
        )

        rv = session.query(*table.c).first()
        self.assertEqual(rv, tuple([42.0] * len(columns)))

    @mock.activate
    def test_parse_date_types(self):
        mock.add(
            mock.POST, 'http://localhost:8123', status=200,
            body=(
                'a\n' +
                'Date\n' +
                '2012-10-25\n'
            )
        )

        table = Table(
            't1', self.metadata(),
            Column('a', types.Date)
        )

        rv = session.query(*table.c).first()
        self.assertEqual(rv, (date(2012, 10, 25), ))

    @mock.activate
    def test_parse_nullable_type(self):
        mock.add(
            mock.POST, 'http://localhost:8123', status=200,
            body=(
                'a\n' +
                'String\n' +
                '\\N\n' +
                '\\\\N\n' +
                '\n'
            )
        )

        table = Table(
            't1', self.metadata(),
            Column('a', types.String)
        )

        rv = session.query(*table.c).all()
        self.assertEqual(rv, [(None, ), ('\\N', ), ('', )])

    @mock.activate
    def check_auth_headers(self, username, password=None):

        def request_callback(request):
            if password is not None:
                # Great! I accidentally found a bug in `requests`.
                # Actually, it's possible to use even an empty
                # username with non-empty password in HTTP Basic
                # Auth. But more important that you can't provide
                # non-empty username without password using
                # `requests` right now.
                #
                # When this bug would be fixed, we can replace a
                # condition with one provided below:
                # `username is not None or password is not None`.
                # It will work, I believe.

                assert 'authorization' in request.headers
                credentials = (username, password) if password is not None else (username,)
                urlified_credentials = ':'.join(credentials)
                encoded_credentials = b64encode(urlified_credentials.encode())
                if compat.PY3:
                    encoded_credentials = encoded_credentials.decode()
                expected_auth_header = 'Basic {}'.format(encoded_credentials)
                assert request.headers['Authorization'] == expected_auth_header
            else:
                assert 'authorization' not in request.headers
            return 200, {}, "OK"

        mock.add_callback(
            mock.POST,
            url='http://localhost:8123',
            callback=request_callback
        )

        credentials = ''

        if username is not None:
            credentials = username
            if password is not None:
                credentials += ':' + password

        credentials += '@' if credentials else ''
        uri = 'clickhouse://{}localhost:8123/default'.format(credentials)
        print(uri)
        assert make_session(create_engine(uri)).execute('kill all humans')

    def test_http_auth_headers(self):
        self.check_auth_headers('username', 'password')
        self.check_auth_headers('username', '')
        self.check_auth_headers('username')
        self.check_auth_headers(None)
        self.check_auth_headers('', 'password')
        self.check_auth_headers('', '')

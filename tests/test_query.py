import unittest
import unittest.mock as mock

import asyncwhois.query


class TestWhoIsQuery(unittest.TestCase):
    @mock.patch("asyncwhois.query.socket")
    def test_whois_query_create_connection(self, mock_socket_lib):
        # test connect
        test_address_tuple_param = ("0.0.0.0", 69)
        test_timeout_param = 10
        with asyncwhois.query.Query()._create_connection(test_address_tuple_param) as _:
            ...
        mock_socket_lib.create_connection.assert_called()
        mock_socket_lib.create_connection.assert_called_with(
            test_address_tuple_param, test_timeout_param
        )

    @mock.patch("asyncwhois.query.Proxy")
    def test_whois_query_proxy_rdns(self, mock_proxy):
        test_address = ("whois.example", 43)
        proxy_url = "socks5://proxy.example:1080"

        for rdns in (True, False):
            with self.subTest(rdns=rdns):
                mock_proxy.reset_mock()
                with asyncwhois.query.Query(rdns=rdns)._create_connection(
                    test_address, proxy_url
                ):
                    ...

                mock_proxy.from_url.assert_called_once_with(proxy_url, rdns=rdns)
                mock_proxy.from_url.return_value.connect.assert_called_once_with(
                    *test_address, timeout=10
                )

    @mock.patch("asyncwhois.query.socket.socket")
    def test_whois_query_send_and_recv(self, mock_socket_instance):
        test_data_send_string = "a-domain-to-send"
        test_data_recv_bytes = b""  # empty so _send_and_recv does not infinite loop
        mock_socket_instance.recv.return_value = test_data_recv_bytes
        asyncwhois.query.Query._send_and_recv(
            mock_socket_instance, test_data_send_string
        )
        mock_socket_instance.recv.assert_called()
        mock_socket_instance.sendall.assert_called()
        mock_socket_instance.sendall.assert_called_with(test_data_send_string.encode())


class TestAsyncWhoIsQuery(unittest.IsolatedAsyncioTestCase):
    @mock.patch("asyncwhois.query.AsyncProxy")
    async def test_whois_query_proxy_rdns(self, mock_proxy):
        test_address = ("whois.example", 43)
        proxy_url = "socks5://proxy.example:1080"
        mock_proxy.from_url.return_value.connect = mock.AsyncMock(
            return_value=mock.sentinel.socket
        )
        writer = mock.Mock()
        writer.wait_closed = mock.AsyncMock()

        with mock.patch(
            "asyncwhois.query.asyncio.open_connection",
            new=mock.AsyncMock(return_value=(mock.sentinel.reader, writer)),
        ):
            async with asyncwhois.query.Query(rdns=False)._aio_create_connection(
                test_address, proxy_url
            ):
                ...

        mock_proxy.from_url.assert_called_once_with(proxy_url, rdns=False)
        mock_proxy.from_url.return_value.connect.assert_awaited_once_with(
            *test_address, timeout=10
        )

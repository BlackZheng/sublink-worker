import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { parseVless } from '../src/parsers/protocols/vlessParser.js';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';

const xhttpUrl = 'vless://abcdefg1-a12b-a12b-a12b-abcdefg12345@myhost.example.com:2096?type=xhttp&encryption=none&path=/download&host=myhost.example.com&mode=auto&x_padding_bytes=100-1000&extra={"xPaddingBytes":"200-2000"}&security=tls&fp=chrome&alpn=h2,http/1.1&sni=myhost.example.com#MY_XHTTP_NODE';

describe('VLESS xhttp support', () => {
    it('parses xhttp transport options from VLESS URL', () => {
        const proxy = parseVless(xhttpUrl);

        expect(proxy.transport).toEqual({
            type: 'xhttp',
            path: '/download',
            host: 'myhost.example.com',
            mode: 'auto',
            x_padding_bytes: '100-1000'
        });
        expect(proxy.tls).toMatchObject({
            enabled: true,
            server_name: 'myhost.example.com',
            insecure: false,
            utls: {
                enabled: true,
                fingerprint: 'chrome'
            }
        });
        expect(proxy.alpn).toEqual(['h2', 'http/1.1']);
    });

    it('uses extra.xPaddingBytes when x_padding_bytes is not explicit', () => {
        const proxy = parseVless('vless://abcdefg1-a12b-a12b-a12b-abcdefg12345@myhost.example.com:2096?type=xhttp&path=/download&host=myhost.example.com&mode=auto&extra={"xPaddingBytes":"100-1000"}&security=tls&sni=myhost.example.com#MY_XHTTP_NODE');

        expect(proxy.transport.x_padding_bytes).toBe('100-1000');
    });

    it('outputs mihomo xhttp-opts for VLESS xhttp URI subscriptions', async () => {
        const builder = new ClashConfigBuilder(xhttpUrl, 'minimal', [], null, 'zh-CN', 'mihomo/1.19');
        const config = yaml.load(await builder.build());
        const proxy = config.proxies.find(item => item.name === 'MY_XHTTP_NODE');

        expect(proxy).toMatchObject({
            name: 'MY_XHTTP_NODE',
            type: 'vless',
            server: 'myhost.example.com',
            port: 2096,
            uuid: 'abcdefg1-a12b-a12b-a12b-abcdefg12345',
            tls: true,
            servername: 'myhost.example.com',
            network: 'xhttp',
            tfo: false,
            'skip-cert-verify': false,
            udp: true,
            'client-fingerprint': 'chrome',
            alpn: ['h2', 'http/1.1']
        });
        expect(proxy['xhttp-opts']).toEqual({
            host: 'myhost.example.com',
            path: '/download',
            mode: 'auto',
            'x-padding-bytes': '100-1000'
        });
        expect(proxy['ws-opts']).toBeUndefined();
        expect(proxy['grpc-opts']).toBeUndefined();
    });

    it('round-trips mihomo VLESS xhttp YAML subscriptions', async () => {
        const input = `proxies:
  - name: MY_XHTTP_NODE
    type: vless
    server: myhost.example.com
    port: 2096
    uuid: abcdefg1-a12b-a12b-a12b-abcdefg12345
    tls: true
    servername: myhost.example.com
    network: xhttp
    tfo: false
    skip-cert-verify: false
    udp: true
    client-fingerprint: chrome
    alpn:
      - h2
      - http/1.1
    xhttp-opts:
      host: myhost.example.com
      path: /download
      mode: auto
      x-padding-bytes: "100-1000"`;
        const builder = new ClashConfigBuilder(input, 'minimal', [], null, 'zh-CN', 'mihomo/1.19');
        const config = yaml.load(await builder.build());
        const proxy = config.proxies.find(item => item.name === 'MY_XHTTP_NODE');

        expect(proxy.network).toBe('xhttp');
        expect(proxy['xhttp-opts']).toEqual({
            host: 'myhost.example.com',
            path: '/download',
            mode: 'auto',
            'x-padding-bytes': '100-1000'
        });
        expect(proxy['client-fingerprint']).toBe('chrome');
        expect(proxy.alpn).toEqual(['h2', 'http/1.1']);
    });
});

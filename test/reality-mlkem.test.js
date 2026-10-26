import { afterEach, describe, expect, it, vi } from 'vitest';
import yaml from 'js-yaml';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { CLASH_CONFIG } from '../src/config/index.js';

vi.mock('../src/parsers/subscription/httpSubscriptionFetcher.js', async (importOriginal) => ({
    ...await importOriginal(),
    fetchSubscriptionWithFormat: vi.fn()
}));
import { fetchSubscriptionWithFormat } from '../src/parsers/subscription/httpSubscriptionFetcher.js';

const protocols = ['vless', 'trojan'];
const uuid = '00000000-0000-4000-8000-000000000001';

function shareLink(protocol, value, security = 'reality') {
    const url = new URL(`${protocol}://${protocol === 'vless' ? uuid : 'test-password'}@example.com:443`);
    url.search = new URLSearchParams({ security, type: 'tcp', sni: 'example.com', fp: 'chrome', pbk: 'test-public-key', sid: 'ab' });
    if (value !== undefined) url.searchParams.set('support-x25519mlkem768', value);
    url.hash = 'Test-Reality';
    return url.toString();
}

function clashProxy(protocol, value) {
    return {
        name: 'Test-Reality',
        type: protocol,
        server: 'example.com',
        port: 443,
        ...(protocol === 'vless' ? { uuid } : { password: 'test-password' }),
        tls: true,
        servername: 'example.com',
        'client-fingerprint': 'chrome',
        'reality-opts': {
            'public-key': 'test-public-key',
            'short-id': 'ab',
            ...(value !== undefined ? { 'support-x25519mlkem768': value } : {})
        }
    };
}

async function buildClash(input, baseConfig) {
    const builder = new ClashConfigBuilder(input, 'minimal', [], baseConfig, 'zh-CN', 'mihomo/1.19.33');
    return yaml.load(await builder.build());
}

afterEach(() => vi.clearAllMocks());

describe.each(protocols)('%s REALITY ML-KEM conversion', (protocol) => {
    it.each([
        [undefined, true], ['true', true], ['false', false], ['1', true], ['0', false]
    ])('converts a share-link value of %s to the boolean %s', async (value, expected) => {
        const config = await buildClash(shareLink(protocol, value));

        expect(config.proxies[0]['reality-opts']).toEqual({
            'public-key': 'test-public-key',
            'short-id': 'ab',
            'support-x25519mlkem768': expected
        });
    });

    it.each([
        [undefined, true], [true, true], [false, false], ['false', false]
    ])('round-trips a Clash YAML value of %s as %s', async (value, expected) => {
        const input = yaml.dump({ proxies: [clashProxy(protocol, value)] });
        const config = await buildClash(input);

        expect(config.proxies[0]['reality-opts']['support-x25519mlkem768']).toBe(expected);
        expect(config.proxies[0]['client-fingerprint']).toBe('chrome');
    });

    it('keeps the field out of ordinary TLS nodes', async () => {
        const config = await buildClash(shareLink(protocol, 'true', 'tls'));

        expect(config.proxies[0].tls).toBe(true);
        expect(config.proxies[0]).not.toHaveProperty('reality-opts');
    });

    it.each([true, false])('does not leak the Mihomo-only value %s into sing-box output', async (value) => {
        const input = yaml.dump({ proxies: [clashProxy(protocol, value)] });
        const builder = new SingboxConfigBuilder(input, 'minimal', [], null, 'zh-CN', 'test');
        const parsed = (await builder.parseCustomItems())[0];
        const original = structuredClone(parsed);
        const converted = builder.convertProxy(parsed);

        expect(converted.tls.reality).toEqual({ enabled: true, public_key: 'test-public-key', short_id: 'ab' });
        expect(JSON.stringify(converted)).not.toContain('support_x25519mlkem768');
        expect(JSON.stringify(converted)).not.toContain('support-x25519mlkem768');
        expect(parsed).toEqual(original);
    });
});

describe('REALITY defaults in base templates and proxy-providers', () => {
    it('normalizes base-template nodes while retaining explicit opt-outs', async () => {
        const baseConfig = {
            ...CLASH_CONFIG,
            proxies: [clashProxy('vless'), { ...clashProxy('vless', false), name: 'Legacy-Reality' }]
        };
        const config = await buildClash('', baseConfig);

        expect(config.proxies.map(proxy => proxy['reality-opts']['support-x25519mlkem768'])).toEqual([true, false]);
        expect(baseConfig.proxies[0]['reality-opts']).not.toHaveProperty('support-x25519mlkem768');
    });

    it('retains automatic provider refreshes and supplies a conditional default for remote nodes', async () => {
        fetchSubscriptionWithFormat.mockResolvedValue({
            content: yaml.dump({ proxies: [clashProxy('vless')] }),
            format: 'clash',
            url: 'https://example.com/clash-sub'
        });
        const config = await buildClash('https://example.com/clash-sub');
        const provider = Object.values(config['proxy-providers'])[0];

        expect(provider.url).toBe('https://example.com/clash-sub');
        expect(provider.interval).toBe(3600);
        expect(provider.override['override-expr']).toHaveLength(1);
        expect(provider.override['override-expr'][0]).toContain('select(');
        expect(provider.override['override-expr'][0]).toContain('["support-x25519mlkem768"] == null');
    });

    it('preserves provider overrides and adds the default once', async () => {
        const baseConfig = {
            ...CLASH_CONFIG,
            proxies: [clashProxy('vless')],
            'proxy-providers': {
                legacy: {
                    type: 'inline',
                    payload: [clashProxy('vless', false)],
                    override: { udp: false, 'override-expr': ['.tfo = false'] }
                }
            }
        };
        const builder = new ClashConfigBuilder('', 'minimal', [], baseConfig, 'zh-CN', 'mihomo/1.19.33');
        await builder.build();
        const config = yaml.load(builder.formatConfig());
        const provider = config['proxy-providers'].legacy;

        expect(provider.override.udp).toBe(false);
        expect(provider.override['override-expr']).toHaveLength(2);
        expect(provider.override['override-expr'][0]).toBe('.tfo = false');
        expect(provider.payload[0]['reality-opts']['support-x25519mlkem768']).toBe(false);
        expect(baseConfig['proxy-providers'].legacy.override['override-expr']).toEqual(['.tfo = false']);
    });
});

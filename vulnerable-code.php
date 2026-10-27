<?php
/**
 * Vulnerable Code Snippets from Spotweb
 * This demonstrates the Open Redirect vulnerability
 * DO NOT USE IN PRODUCTION
 */

// ============================================
// VULNERABLE CODE - Location 1
// File: templates/we1rdo/login.inc.php (Lines 5-8)
// Also in: templates/modern/login.inc.php, templates/mobile/login.inc.php
// ============================================

/**
 * After successful login, user is redirected using http_referer from form
 */
// Line 5-8:
if (isset($data['performredirect']) && ($result->isSuccess())) {
    // VULNERABLE: $loginform['http_referer'] comes from POST data
    // User can submit any URL in the hidden form field
    $tplHelper->redirect($loginform['http_referer']);
}

// The hidden form field (line 41):
// <input type="hidden" name="loginform[http_referer]" value="<?php echo $http_referer; ?>">
// Attacker can modify this to any external URL

// ============================================
// VULNERABLE CODE - Location 2
// File: lib/SpotTemplateHelper.php (Lines 1586-1589)
// ============================================

/**
 * Redirect function - NO URL VALIDATION
 */
public function redirect($url)
{
    // VULNERABLE: No validation of $url
    // Accepts any URL including external domains, javascript:, data: URIs
    header('Location: '.$url);
}

// ============================================
// VULNERABLE CODE - Location 3
// File: lib/SpotReq.php (Lines 56-57)
// ============================================

/**
 * getForm() adds http_referer to form data
 */
public function getForm($formname)
{
    // ...
    if (!isset($form['http_referer'])) {
        // Falls back to HTTP_REFERER header, but can be overridden by POST
        $form['http_referer'] = $this->getHttpReferer();
    }
    return $form;
}

// ============================================
// FIXED CODE - Recommended Remediation
// ============================================

/**
 * Fixed redirect function with URL validation
 */
public function redirectFixed($url)
{
    // Validate URL is local before redirecting
    if (!$this->isLocalUrl($url)) {
        // Fallback to configured Spotweb URL
        $url = $this->_settings->get('spotweburl');
    }

    // Remove any header injection attempts
    $url = str_replace(["\r", "\n"], '', $url);

    header('Location: ' . $url);
}

/**
 * Check if URL is local/same-origin
 */
private function isLocalUrl($url)
{
    if (empty($url)) {
        return false;
    }

    // Block dangerous URI schemes (javascript:, data:, vbscript:, etc.)
    $scheme = parse_url($url, PHP_URL_SCHEME);
    if ($scheme && !in_array(strtolower($scheme), ['http', 'https'], true)) {
        return false;
    }

    // Allow relative URLs (no host specified)
    $parsed = parse_url($url);
    if (empty($parsed['host'])) {
        return true;
    }

    // Check if host matches configured Spotweb host
    $spotwebUrl = $this->_settings->get('spotweburl');
    $spotwebHost = parse_url($spotwebUrl, PHP_URL_HOST);

    return strcasecmp($parsed['host'], $spotwebHost) === 0;
}

// ============================================
// ALTERNATIVE FIX - Whitelist approach
// ============================================

/**
 * Alternative: Only allow redirect to known internal pages
 */
public function redirectSafe($url)
{
    $allowedPaths = [
        '/',
        '/?page=index',
        '/?page=spots',
        '/?page=getspot',
        '/?page=search',
    ];

    $parsed = parse_url($url);
    $path = ($parsed['path'] ?? '/') . (isset($parsed['query']) ? '?' . $parsed['query'] : '');

    // Check if path starts with any allowed path
    $isAllowed = false;
    foreach ($allowedPaths as $allowed) {
        if (strpos($path, $allowed) === 0) {
            $isAllowed = true;
            break;
        }
    }

    if (!$isAllowed) {
        $url = $this->_settings->get('spotweburl');
    }

    header('Location: ' . $url);
}

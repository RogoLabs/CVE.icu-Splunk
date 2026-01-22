/**
 * CVE.ICU Setup Page Controller
 * Simple, clean setup completion handler
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc) {
    'use strict';
    
    var CONFIG = {
        REST_ENDPOINT: '/servicesNS/nobody/TA-cveicu/ta_cveicu/ta_cveicu_settings/github_settings',
        DASHBOARD_URL: '/app/TA-cveicu/cve_dashboard_instant',
        REDIRECT_DELAY: 500
    };
    
    function getLocale() {
        var match = window.location.pathname.match(/^\/([a-z]{2}-[A-Z]{2})\//);
        return match ? match[1] : 'en-US';
    }
    
    function buildUrl(path) {
        return '/' + getLocale() + path;
    }
    
    function getFormKey() {
        if (window.$C && window.$C.FORM_KEY) {
            return window.$C.FORM_KEY;
        }
        var match = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
        return match ? match[1] : '';
    }
    
    function showStatus(type, message) {
        $('#setup-status')
            .removeClass('loading success')
            .addClass(type)
            .text(message)
            .fadeIn(200);
    }
    
    function setButtonState(disabled, text) {
        var $btn = $('#launch-btn');
        $btn.prop('disabled', disabled);
        $btn.find('.btn-text').text(text || 'Launch Dashboard');
        $btn.find('.btn-spinner').toggle(disabled);
    }
    
    function completeSetup() {
        showStatus('loading', 'Configuring CVE.ICU...');
        setButtonState(true, 'Setting up...');
        
        var restUrl = buildUrl('/splunkd/__raw' + CONFIG.REST_ENDPOINT);
        
        $.ajax({
            url: restUrl,
            type: 'POST',
            data: { github_token: '' },
            headers: {
                'X-Splunk-Form-Key': getFormKey(),
                'X-Requested-With': 'XMLHttpRequest'
            },
            timeout: 10000
        })
        .always(function() {
            showStatus('success', 'Setup complete! Launching dashboard...');
            setButtonState(true, 'Redirecting...');
            
            setTimeout(function() {
                window.location.href = buildUrl(CONFIG.DASHBOARD_URL);
            }, CONFIG.REDIRECT_DELAY);
        });
    }
    
    $(document).ready(function() {
        $('#launch-btn').on('click', function(e) {
            e.preventDefault();
            if (!$(this).prop('disabled')) {
                completeSetup();
            }
        });
        
        console.log('[CVE.ICU] Setup page ready');
    });
});

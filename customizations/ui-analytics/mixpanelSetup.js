/**
 * DEV NOTE: All the code in this file is moved to
 * ULC/ui/web-components/src/components/shared/cp-ui-analytics/mixpanel/mixpanel-utils.service.ts
 * BUT some parts of the code is retained to ensure the consent popup is able to enable/disable mixpanel analytics.
 * This file will removed as part of PHX-6(https://webpros.atlassian.net/browse/PHX-6).
 */

const mpUserSession = "mp_cp_user_session";
const mpResetSession = "mp_cp_reset_session";

/**
 * Enables analytics first time after login if user's consent is set to 'Allow' or 'on'
 * @param mixpanelConfig    An object that includes mixpanel specific data.
 */
var enableAnalyticsForFirstTime = function (mixpanelConfig) {
    // Store user logged in event when loaded the first time.
    if (!sessionStorage.getItem(mpUserSession)) {
        sessionStorage.setItem(mpUserSession, mixpanelConfig.loginUser);
    }
    // window["mixpanel"] is sent to make sure we are using the same mixpanel instance in both the places (here and web component.)
    _registerMixpanel(window["mixpanel"], mixpanelConfig.cpAnalyticsData);
}

/**
 * Registers Mixpanel for the workspace (cPanel, Webmail or WHM)
 * that calls this function.
 * Opts in analytics tracking.
 * Creates super properties and that can be accessed by all events.
 */
var _registerMixpanel = function (mixpanel, analyticsData) {
    if (Object.keys(analyticsData).length === 0){return;}

    // Call Mixpanel's opt-in method.
    if (!mixpanel.has_opted_in_tracking()) {
        // We don't want this to create an unnecessary event.
        mixpanel.opt_in_tracking({ "track": () => { } });
    }
    const tokenRegex = /\/cpsess\d+\//i;
    // Sanitize the url path.
    var path = _getUrlPath().replace( tokenRegex, '/' );
    var pageTitle = analyticsData.product_interface + '-' + (analyticsData.product_feature || path);

    // Register $current_url before the identify request to ensure it uses
    // the sanitized path in all requests.
    mixpanel.register({
        $current_url: path,
    });

    // Identify the user only if the UUID exists.
    if (analyticsData.UUID) {
        mixpanel.identify(analyticsData.UUID);
    } else if (!sessionStorage.getItem(mpResetSession)) {
        // When UUID doesn't exist, Mixpanel SDK uses the previous UUID
        // stored in the cookie. That may end up identifying the current user
        // with a previous user's login. To avoid such situation, we are clearing
        // old data and recreating the props for the current user IF UUID doesn't exist.
        mixpanel.reset();
        sessionStorage.setItem(mpResetSession, true);
    }

    // Identify the team user only if is_team_user is true and get roles
    if (analyticsData.is_team_user) {
        mixpanel.people.set({"team_user_roles" : analyticsData.team_user_roles});
    }

    // Register MixPanel. The properties set during registration are super properties.
    // These super properties are sent with all events tracked by Mixpanel.
    mixpanel.register({
        // analytics data
        ...analyticsData
    });

    mixpanel.set_group("company_id", analyticsData.company_id);

    mixpanel.people.set({
        "product_locale"                         : analyticsData.product_locale,
        "product_version"                        : analyticsData.product_version,
        "product_trial_status"                   : analyticsData.product_trial_status,
        "server_current_license_kind"            : analyticsData.server_current_license_kind,
        "server_main_ip"                         : analyticsData.server_main_ip,
        "server_operating_system"                : analyticsData.server_operating_system,
        "server_is_nat"                          : analyticsData.is_nat,
        "account_transferred_or_restored"        : analyticsData.TRANSFERRED_OR_RESTORED,
    });

    // Track Page view event.
    mixpanel.track(pageTitle, {});
}

/**
 * Opts out of analytics tracking for the
 * workspace (cPanel, Webmail or WHM)
 * from where this function is called.
 * Additionally, it also clears the super properties
 * that where set during the opt in phase.
 */
optOutOfAnalytics = function(){
    // window["mixpanel"] is explicitly set to make sure we are using the same mixpanel instance in both the places (here and web component.)
    var mxp = window["mixpanel"];
    if (mxp && mxp.has_opted_in_tracking()) {
        mxp.clear_opt_in_out_tracking();
        // Clear all the super properties before opting out.
        mxp.reset();
        mxp.opt_out_tracking();
    }
}

/**
 * Returns the sanitized path of the url.
 */
function _getUrlPath(){
    var path = window.location.pathname;
    if (path) {
        var wholepath = path.split('/');
        var custompath = wholepath.slice(2);
        path = '/' + custompath.join('/');
    }
    return path;
}

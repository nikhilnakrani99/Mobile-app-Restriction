from odoo import http
from odoo.http import request
from odoo.tools.translate import _
import odoo
from odoo.addons.web.controllers.main import _get_login_redirect_url
from odoo.addons.web.controllers.utils import ensure_db
import logging
_logger = logging.getLogger(__name__)

SIGN_UP_REQUEST_PARAMS = {'db', 'login', 'debug', 'token', 'message', 'error', 'scope', 'mode',
                          'redirect', 'redirect_hostname', 'email', 'name', 'partner_id',
                          'password', 'confirm_password', 'city', 'country_id', 'lang', 'signup_email'}

class RestrictMobileWebLogin(http.Controller):
    @http.route('/web/login', type='http', auth="none")
    def web_login(self, redirect=None, **kw):
        ensure_db()
        request.params['login_success'] = False


        if request.httprequest.method == 'GET' and redirect and request.session.uid:
            return request.redirect(redirect)

        if request.env.uid is None:
            if request.session.uid is None:
                request.env["ir.http"]._auth_method_public()
            else:
                request.update_env(user=request.session.uid)

        values = {k: v for k, v in request.params.items() if k in SIGN_UP_REQUEST_PARAMS}
        try:
            values['databases'] = http.db_list()
        except odoo.exceptions.AccessDenied:
            values['databases'] = None

        # Mobile validation
        user_agent = request.httprequest.headers.get('User-Agent')
        is_mobile = any(device in user_agent for device in ['Mobile', 'Android', 'iPhone', 'Darwin', 'iPad', 'iOS','Odoo Mobile'])
        _logger.info("User-Agent: %s", user_agent)
        _logger.info("Is Mobile Device: %s", is_mobile)


        login = request.params.get('login')
        user = request.env['res.users'].sudo().search([('login', '=', login)], limit=1)


        # Check mobile login restriction
        if user and is_mobile and user.restrict_mobile_login:
            _logger.warning("Mobile login restricted for user: %s on a Mobile browser", user.login)
            values['error'] = _("You are not allowed to log in from a mobile device. Please use a desktop browser.")
        #


        if request.httprequest.method == 'POST':
            if not values.get('error'):  # Proceed only if there are no errors
                try:
                    uid = request.session.authenticate(request.db, request.params['login'], request.params['password'])
                    request.params['login_success'] = True
                    redirect_url = _get_login_redirect_url(uid, redirect=redirect)
                    return request.redirect(redirect_url)
                except odoo.exceptions.AccessDenied as e:
                    if e.args == odoo.exceptions.AccessDenied().args:
                        values['error'] = _("Wrong login/password")
                    else:
                        values['error'] = e.args[0]
        else:
            if 'error' in request.params and request.params.get('error') == 'access':
                values['error'] = _('Only employees can access this database. Please contact the administrator.')

        if 'login' not in values and request.session.get('auth_login'):
            values['login'] = request.session.get('auth_login')

        if not odoo.tools.config['list_db']:
            values['disable_database_manager'] = True

        response = request.render('web.login', values)
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "frame-ancestors 'self'"
        return response


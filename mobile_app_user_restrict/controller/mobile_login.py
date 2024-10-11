from odoo.exceptions import AccessError,UserError
from odoo import http,_
from odoo.http import request
import odoo
from odoo.tools.translate import _
import logging
_logger = logging.getLogger(__name__)

class RestrictMobileAppLogin(http.Controller):

    @http.route('/web/session/authenticate', type='json', auth="none")
    def authenticate(self, db, login, password, base_location=None):

        if not http.db_filter([db]):
            raise AccessError("Database not found.")

        # Mobile validation
        user_agent = request.httprequest.headers.get('User-Agent')
        is_mobile = any(device in user_agent for device in ['Mobile', 'Android', 'iPhone', 'Darwin', 'iPad', 'iOS','Odoo Mobile'])
        
        
        _logger.info("User-Agent: %s", user_agent)
        _logger.info("Is Mobile Device: %s", is_mobile)

        pre_uid = request.session.authenticate(db, login, password)
        if pre_uid != request.session.uid:
            return {'uid': None}

        request.session.db = db
        registry = odoo.modules.registry.Registry(db)
        with registry.cursor() as cr:
            env = odoo.api.Environment(cr, request.session.uid, request.session.context)

            # Check mobile login restriction
            user = env['res.users'].sudo().browse(request.session.uid)
            if user.restrict_mobile_login and is_mobile:
                _logger.warning("Mobile login restricted for user: %s on a Mobile App", user.login)

                raise UserError(_("You are not allowed to log in from a mobile device. Please use a desktop browser."))
            #

            if not request.db and not request.session.is_explicit:

                http.root.session_store.rotate(request.session, env)
                request.future_response.set_cookie(
                    'session_id', request.session.sid,
                    max_age=http.SESSION_LIFETIME, httponly=True
                )

            return env['ir.http'].session_info()


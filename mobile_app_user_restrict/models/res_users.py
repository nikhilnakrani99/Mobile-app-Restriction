from odoo import models, fields

class ResUsers(models.Model):
    _inherit = 'res.users'

    restrict_mobile_login = fields.Boolean(string='Restrict Mobile Login')

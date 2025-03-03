# Copyright 2015 LasLabs Inc.
# Copyright 2018 Modoolar <info@modoolar.com>.
# Copyright 2019 initOS GmbH
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).
{
    "name": "Password Security",
    "summary": "Allow admin to set password security requirements.",
    "version": "16.0.1.0.2",
    "author": "LasLabs, "
    "Onestein, "
    "Kaushal Prajapati, "
    "Tecnativa, "
    "initOS GmbH, "
    "Omar Nasr, "
    "Odoo Community Association (OCA)",
    "category": "Base",
    "depends": [
        "auth_signup",
        "auth_password_policy_signup",
    ],
    "website": "https://github.com/OCA/server-auth",
    "license": "LGPL-3",
    "data": [
        "views/res_config_settings_views.xml",
        "security/ir.model.access.csv",
        "security/res_users_pass_history.xml",
    ],
    "demo": [
        "demo/res_users.xml",
    ],
    "installable": True,
    "post_init_hook": "post_init_hook",
}

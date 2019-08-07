# Copyright 2018 BlueCat Networks. All rights reserved.

# Various Flask framework items.
import os
import sys
import json
import codecs

from flask import url_for, redirect, render_template, flash, g, request,jsonify
from bluecat import route, util
import config.default_config as config
from main_app import app
from .Debian_CVE_Analysis_form import GenericFormTemplate
from .DebianCVEAnalysis import main, insertCVEnumber, checkRELFormat, getREL, getCVEnumber
from .config import config_local



def module_path():
    encoding = sys.getfilesystemencoding()
    return os.path.dirname(os.path.abspath(__file__))


# The workflow name must be the first part of any endpoints defined in this file.
# If you break this rule, you will trip up on other people's endpoint names and
# chaos will ensue.
@route(app, '/Debian_CVE_Analysis/Debian_CVE_Analysis_endpoint', methods=['POST','GET'])
@util.workflow_permission_required('Debian_CVE_Analysis_page')
@util.exception_catcher
def Debian_CVE_Analysis_Debian_CVE_Analysis_page():
    form = GenericFormTemplate()
    # Remove this line if your workflow does not need to select a configuration
   # form.configuration.choices = util.get_configurations(default_val=True)
    return render_template(
        'Debian_CVE_Analysis_page.html',
        form=form,
        text=util.get_text(module_path(), config.language),
        options=g.user.get_options(),
    )
#
# @route(app, '/Debian_CVE_Analysis/form1', methods=['POST'])
# @util.workflow_permission_required('Debian_CVE_Analysis_page')
# @util.exception_catcher
# def Debian_CVE_Analysis_Debian_CVE_Analysis_page_form1():
#     form = GenericFormTemplate()
#     # Remove this line if your workflow does not need to select a configuration
#     #form.configuration.choices = util.get_configurations(default_val=True)
#     if form.validate_on_submit():
#         print(form.ip_address.data)
#         print(form.ssh_user.data)
#         print(form.password.data)
#         print(form.cve.data)
#         print(form.submit.data)
#         #--------#
#         server = form.ip_address.data
#         username = form.ssh_user.data
#         password = form.password.data
#         cve = form.cve.data
#
#         # Put form processing code here
#         #print("before main")
#         main(cve = cve.replace('CVE-',''),server = server, username = username, password = password)
#         # --------#
#         g.user.logger.info('SUCCESS')
#         flash('success', 'succeed')
#         return redirect(url_for('Debian_CVE_AnalysisDebian_CVE_Analysis_Debian_CVE_Analysis_page'))
#     else:
#         g.user.logger.info('Form data was not valid.')
#         return render_template(
#             'Debian_CVE_Analysis_page.html',
#             form=form,
#             text=util.get_text(module_path(), config.language),
#             options=g.user.get_options(),
#        )

@route(app, '/Debian_CVE_Analysis/yield1', methods=['GET','POST'])
@util.workflow_permission_required('Debian_CVE_Analysis_page')
@util.exception_catcher
def output():
    if request.method=='POST':
        cvelist = request.form.get('cve').strip()
        server = request.form.get('ip_address').strip()
        password = request.form.get('password')
        username = request.form.get('ssh_user').strip()
        cves = [val.strip() for val in cvelist.split(',')]
        print(cves)
        Allouts = ""
        for cve in cves:
            initialPrint = "<div> "+ cve + "<br />" + "</div>"
            out = main(cve=cve.replace('CVE-', ''), server=server, username=username, password=password)
            # --------#
            g.user.logger.info('SUCCESS')
            print("request method:",request.method)
            #out = str(request.args.get('ip_address'))
            #out=request.form
            print(out)
            out = "".join([val for val in out]).split('\n')
            out = "<div>"+"".join([val + "<br />" for val in out]) + "</div>"
            print("InitialPrint", initialPrint)
            print("out", out)
            Allouts += initialPrint +out + "<br />"
        return jsonify(Allouts)


@route(app, '/Debian_CVE_Analysis/yield2', methods=['GET','POST'])
@util.workflow_permission_required('Debian_CVE_Analysis_page')
@util.exception_catcher
def output_2():
    if request.method == 'POST':
        cve = request.form.get('cve').strip()
        rel = request.form.get('rel').strip()
        admin_password = request.form.get('password2')
        rel = rel.upper()
        if rel=="":
            type = request.form.get('action')
            if type == 'Update':
                return jsonify("Please enter REL")
            relList = getREL(cve)
            cve = cve.replace('CVE-', '')
            if relList == False:


                cveID = getCVEnumber(cve)
                if cveID is None:
                    return jsonify("Please check the CVE format")

                out = "<p> No REL values of CVE number : CVE-" + cve + "<br /> </p>"
                return jsonify(out)
            else:
                out = "<p> Existing REL values of CVE number : CVE-" + cve + "<br /> </p> <p>"
                for val in relList:
                    out += '{' + val + '}' + ' '
                out += "<br /> </p>"
                return jsonify(out)


        relFormat = checkRELFormat(rel)

        if relFormat == "goodREL":
            if admin_password == config_local['Admin_password']:
                out = insertCVEnumber(cve=cve, rel=rel)
            else:
                out = "Please enter valid password"
            return jsonify(out)
        else:

            return jsonify("Please check REL-XXX format")


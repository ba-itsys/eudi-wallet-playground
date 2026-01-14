<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        Register OID4VP Credential
    <#elseif section = "form">
        <form id="oid4vpRegisterForm"
              action="${url.loginAction}"
              method="post"
              data-oid4vp-nonce="${nonce!}"
              data-oid4vp-dcql-query="${dcqlQuery!}"
              data-oid4vp-request-object="${dcApiRequestObject!}">
            <input type="hidden" id="state" name="state" value="${state!}"/>
            <input type="hidden" id="vp_token" name="vp_token"/>
            <input type="hidden" id="response" name="response"/>
            <input type="hidden" id="error" name="error"/>
            <input type="hidden" id="error_description" name="error_description"/>
        </form>

        <div class="${properties.kcFormGroupClass!}">
            <p>Register a verifiable credential so you can authenticate with OID4VP next time.</p>
        </div>

        <div class="${properties.kcFormGroupClass!}">
            <input id="oid4vpRegisterButton"
                   type="button"
                   class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                   value="Register via Digital Credentials API"/>
        </div>

        <div class="${properties.kcFormGroupClass!}">
            <pre id="oid4vpRegisterLog" style="font-size: 12px; line-height: 1.2; max-height: 240px; overflow: auto;"></pre>
        </div>

        <script nonce="${cspNonce!}" src="${url.resourcesPath}/js/oid4vp-dc-api.js"></script>
    </#if>
</@layout.registrationLayout>

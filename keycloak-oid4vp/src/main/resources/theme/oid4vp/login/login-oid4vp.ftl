<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        Login with OID4VP
    <#elseif section = "form">
        <form id="oid4vpForm"
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
            <p>Use a verifiable credential to authenticate via OpenID for Verifiable Presentations (OID4VP).</p>
        </div>

        <div class="${properties.kcFormGroupClass!}">
            <input id="oid4vpStartButton"
                   type="button"
                   class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                   value="Use Digital Credentials API"/>
        </div>

        <#assign passwordExecution = "">
        <#if auth?? && auth.authenticationSelections??>
            <#list auth.authenticationSelections as authenticationSelection>
                <#if authenticationSelection.authenticationExecution?? && authenticationSelection.authenticationExecution.authenticator?? && authenticationSelection.authenticationExecution.authenticator == "auth-username-password-form">
                    <#assign passwordExecution = authenticationSelection.authExecId>
                </#if>
            </#list>
        </#if>
        <#if passwordExecution?has_content>
            <form id="kc-oid4vp-back-to-password-form" action="${url.loginAction}" method="post" novalidate="novalidate">
                <input type="hidden" name="authenticationExecution" value="${passwordExecution}"/>
                <button id="kc-oid4vp-back-to-password"
                        type="submit"
                        class="${properties.kcButtonClass!} ${properties.kcButtonLinkClass!}">
                    Back to password login
                </button>
            </form>
        </#if>

        <div class="${properties.kcFormGroupClass!}">
            <pre id="oid4vpLog" style="font-size: 12px; line-height: 1.2; max-height: 240px; overflow: auto;"></pre>
        </div>

        <script nonce="${cspNonce!}" src="${url.resourcesPath}/js/oid4vp-dc-api.js"></script>
    </#if>
</@layout.registrationLayout>

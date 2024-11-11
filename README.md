# iis-csp-nonce
Native IIS module to add a CSP nonce to static sites


add module to C:\Windows\System32\inetsrv\config\applicationHost.config

<globalModules>
  ...
  <add name="CSPNonce" image="%ProgramFiles%\IIS\CSPNonce\CSPNonce.dll" />
  ...
<globalModules/>

<modules>
  ...
  <add name="CSPNonce" />
  ...
</modules>



Add the text string randomNonceGoesHere to your HTML code and your CSP-Header
<style nonce="randomNonceGoesHere">


  
Content-Security-Policy
  default-src 'self'; script-src 'nonce-randomNonceGoesHere' ...

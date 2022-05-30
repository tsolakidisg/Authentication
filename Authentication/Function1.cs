using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Specialized;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;


namespace Authentication
{
    public static class Function1
    {
        [FunctionName("Function1")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = "auth")] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            var header = new { alg = "RS256" };
            var claimTemplate = new
            {
                iss = "3MVG9KlmwBKoC7U1H3Bwx6cd2AzDjrAMtnEEe2iNjNio374UAIoYw.pT5qnHi5gTCmbrXDTkRRmqCueD94vkN",
                sub = "gtsolakidis@deloitte.gr.integr",
                aud = "https://test.salesforce.com",
                exp = GetExpiryDate(),
                jti = Guid.NewGuid(),
            };

            // encoded header
            var headerSerialized = JsonConvert.SerializeObject(header);
            var headerBytes = Encoding.UTF8.GetBytes(headerSerialized);
            var headerEncoded = ToBase64UrlString(headerBytes);

            // encoded claim template
            var claimSerialized = JsonConvert.SerializeObject(claimTemplate);
            var claimBytes = Encoding.UTF8.GetBytes(claimSerialized);
            var claimEncoded = ToBase64UrlString(claimBytes);

            // input
            var input = headerEncoded + "." + claimEncoded;
            var inputBytes = Encoding.UTF8.GetBytes(input);

            ////azure kv
            //var keyVaultUri = (@"https://salesforcecertvault.vault.azure.net/certificates/Salesforce-Middleware-Certificate/f399c6e82b084a578be17bfa19fcc0c1");
            //var _keyVault = "F33E7B5FB639ED5CC9BF3C1AE5F2E9DAF149D0D8";
            ////var _clientId = "377b0a73-f0a4-4bbb-a7bd-811b4744e34c";
            //var serviceTokenProvider = new AzureServiceTokenProvider();
            //var _client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(serviceTokenProvider.KeyVaultTokenCallback));
            //var secret = await _client.GetSecretAsync(keyVaultUri, _keyVault);
            //var privateKeyBytes = Convert.FromBase64String(secret.ToString());
            //var certificate = new X509Certificate2(privateKeyBytes, string.Empty);

            //var cert = new X509Certificate2(privateKeyBytes, "W3lcome!",
            //    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);


            //azure kv
            var keyVaultUri = "https://salesforcecertvault.vault.azure.net/secrets";
            var _keyVault = "Salesforce-Middleware-Certificate/f399c6e82b084a578be17bfa19fcc0c1";
            //var _clientId = "377b0a73-f0a4-4bbb-a7bd-811b4744e34c";
            var serviceTokenProvider = new AzureServiceTokenProvider();
            var _client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(serviceTokenProvider.KeyVaultTokenCallback));
            var secret = await _client.GetSecretAsync();
            var privateKeyBytes = Convert.FromBase64String(secret.ToString());
            var certificate = new X509Certificate2(privateKeyBytes, string.Empty);

            var cert = new X509Certificate2(privateKeyBytes, "W3lcome!",
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);


            //var cert = new X509Certificate2(@"C:\Users\gtsolakidis\OneDrive - Deloitte (O365D)\Documents\PPC - DEH\certificates\server.p12", "W3lcome!",
            //    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            var signingCredentials = new X509SigningCredentials(cert, "RS256");
            var signature = JwtTokenUtilities.CreateEncodedSignature(input, signingCredentials);
            var jwt = headerEncoded + "." + claimEncoded + "." + signature;

            var client = new WebClient();
            client.Encoding = Encoding.UTF8;
            var uri = "https://d7q000002cblcua0--integr.my.salesforce.com/services/oauth2/token";
            var content = new NameValueCollection();

            content["assertion"] = jwt;
            content["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer";

            string response = Encoding.UTF8.GetString(client.UploadValues(uri, "POST", content));

            var result = JsonConvert.DeserializeObject<dynamic>(response);

            return result;
        }


        static int GetExpiryDate()
        {
            var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var currentUtcTime = DateTime.UtcNow;

            var exp = (int)currentUtcTime.AddMinutes(3).Subtract(utc0).TotalSeconds;

            return exp;
        }

        static string ToBase64UrlString(byte[] input)
        {
            return Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }
}

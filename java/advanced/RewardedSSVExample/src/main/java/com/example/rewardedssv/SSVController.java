package com.example.rewardedssv;

import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** SSV controller class */
@RestController
public class SSVController {
  private static final String SIGNATURE_PARAM_NAME = "signature=";
  private static final String KEY_ID_PARAM_NAME = "key_id=";
  private String signature = "";
  private Long keyId;
  private byte[] msg;

  private static Map<Long, ECPublicKey> parsePublicKeysJson(String publicKeysJson)
      throws GeneralSecurityException {
    Map<Long, ECPublicKey> publicKeys = new HashMap<>();
    try {
      JSONArray keys = new JSONObject(publicKeysJson).getJSONArray("keys");
      for (int i = 0; i < keys.length(); i++) {
        JSONObject key = keys.getJSONObject(i);
        publicKeys.put(
            key.getLong("keyId"),
            EllipticCurves.getEcPublicKey(Base64.decode(key.getString("base64"))));
      }
    } catch (JSONException e) {
      throw new GeneralSecurityException("failed to extract trusted signing public keys", e);
    }
    if (publicKeys.isEmpty()) {
      throw new GeneralSecurityException("no trusted keys are available for this protocol version");
    }
    return publicKeys;
  }

  private String publicKeysJson(String stringUrl) throws IOException {
    URL url = new URL(stringUrl);
    HttpURLConnection con = (HttpURLConnection) url.openConnection();
    con.setRequestMethod("GET");

    BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
    String inputLine;
    StringBuffer content = new StringBuffer();
    while ((inputLine = in.readLine()) != null) {
      content.append(inputLine);
    }
    in.close();
    con.disconnect();
    return content.toString();
  }

  private void verify(final byte[] dataToVerify, Long keyId, final byte[] signature, String url)
      throws GeneralSecurityException {
    try {
      Map<Long, ECPublicKey> publicKeys = parsePublicKeysJson(publicKeysJson(url));
      if (publicKeys.containsKey(keyId)) {

        ECPublicKey publicKey = publicKeys.get(keyId);
        EcdsaVerifyJce verifier = new EcdsaVerifyJce(publicKey, HashType.SHA256, EcdsaEncoding.DER);
        verifier.verify(signature, dataToVerify);
      } else {
        throw new GeneralSecurityException("cannot find verifying key with key id: " + keyId);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private void splitSignatureAndKeyId(String rewardUrl) throws GeneralSecurityException {
    URI uri;
    try {
      uri = new URI(rewardUrl);
    } catch (URISyntaxException ex) {
      throw new GeneralSecurityException(ex);
    }
    String queryString = uri.getQuery();
    if (queryString == null) {
      throw new GeneralSecurityException("Missing queryString");
    }
    int i = queryString.indexOf(SIGNATURE_PARAM_NAME);
    if (i == -1) {
      throw new GeneralSecurityException("needs a signature query parameter");
    }
    msg =
        queryString
            .substring(0, i - 1)
            // i - 1 instead of i because of & in the query string
            .getBytes(Charset.forName("UTF-8"));
    String sigAndkeyId = queryString.substring(i);
    i = sigAndKeyId.indexOf(KEY_ID_PARAM_NAME);
    if (i == -1) {
      throw new GeneralSecurityException("needs a key_id query parameter");
    }
    signature =
        sigAndKeyId.substring(
            SIGNATURE_PARAM_NAME.length(), i - 1 /* i - 1 instead of i because of & */);
    keyId = Long.valueOf(sigAndKeyId.substring(i + KEY_ID_PARAM_NAME.length()));
  }

  @PostMapping(value = "/verify", consumes = "application/json")
  public ResponseEntity<?> index(@RequestBody String body) {
    String url = "https://www.gstatic.com/admob/reward/verifier-keys.json";
    JSONObject data = new JSONObject();
    JSONObject response = new JSONObject();
    try {
      JSONObject obj = new JSONObject(body);
      String rewardUrl = obj.getString("reward_url");
      splitSignatureAndKeyId(rewardUrl);
      verify(msg, keyId, Base64.urlSafeDecode(signature), url);
      data.put("msg", new String(msg));
      data.put("key_id", keyId);
      data.put("sig", new String(signature));
      response.put("verified", Boolean.TRUE);
      response.accumulate("data", data);
      return new ResponseEntity<>(response.toString(3), HttpStatus.OK);
    } catch (JSONException | GeneralSecurityException e) {
      HashMap<String, String> map = new HashMap<>();
      map.put("Verified", Boolean.FALSE.toString());
      map.put("data", e.getMessage());
      return new ResponseEntity<>(map, HttpStatus.BAD_REQUEST);
    }
  }
}

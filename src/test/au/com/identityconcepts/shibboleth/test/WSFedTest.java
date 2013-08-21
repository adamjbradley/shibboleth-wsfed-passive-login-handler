package au.com.identityconcepts.shibboleth.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.io.BufferedReader;
import java.text.MessageFormat;
import java.io.OutputStreamWriter;

import au.com.identityconcepts.shibboleth.wsfed.profile.WSFedSTSHandler;

/** WSFed tests */
public class WSFedTest {

    public static void main(String unused[]) throws Exception {

        try {
            WSFedSTSHandler lc = new WSFedSTSHandler(null);
         } catch (Exception e) {
             System.out.println("error: " + e);
         }
   }

}


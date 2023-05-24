import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class Main {
    private static final Logger logger = LogManager.getLogger(Main.class);

    private static Integer httpServerPort = 9011;

    public static void main(String[] args) throws IOException {
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true");
        HttpServer httpServer = HttpServer.create(new InetSocketAddress(httpServerPort), 0);
        httpServer.createContext("/aloha", httpHandler -> {
            byte[] buffer = new byte[1024];
            int lengthRead = httpHandler.getRequestBody().read(buffer);
            String body = new String(buffer, 0, lengthRead);
            String ua = httpHandler.getRequestHeaders().get("User-Agent").get(0).toString();
            System.out.println(body);
            System.out.println(ua);
            JSONObject jsonObject = null;
            try {
                 jsonObject = JSON.parseObject(body);
            }
            catch (Exception e) {
                logger.error("Error encountered which parsing data. ua: {}, data: {}", ua, body);
            }

            String ret = jsonObject.getString("a");
            httpHandler.sendResponseHeaders(200, ret.getBytes(StandardCharsets.UTF_8).length);
            final OutputStream responseBody = httpHandler.getResponseBody();
            responseBody.write(ret.getBytes());
            responseBody.close();
        });
        System.out.println("PoC of CVE-2021-4101. \n Server is listening on: " + httpServerPort);
        httpServer.start();
    }
}

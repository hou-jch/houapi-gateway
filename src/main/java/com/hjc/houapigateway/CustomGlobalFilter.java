package com.hjc.houapigateway;

import com.hjc.hjccommon.model.entity.InterfaceInfo;
import com.hjc.hjccommon.model.entity.User;
import com.hjc.hjccommon.service.InnerInterfaceInfoService;
import com.hjc.hjccommon.service.InnerUserInterfaceInfoService;
import com.hjc.hjccommon.service.InnerUserService;
import com.hjc.hjjcclientsdk.util.SignUtils;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;


/**
 * File Description: CustomGlobalFilter
 * 全局过滤方法
 * Author: hou-jch
 * Date: 2024/9/16
 */
@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {

    @DubboReference
    private InnerUserService  innerUserService;

    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;

    @DubboReference
    private InnerUserInterfaceInfoService innerUserInterfaceInfoService;



    private static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");
    private static final String INTERFACE_HOST = "http://localhost:8123";
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //1.用户发送请求到 API 网关
        //2. 请求日志
        ServerHttpRequest request = exchange.getRequest();
        log.info("请求唯一标识:"+request.getId());
        log.info("请求路径:"+ request.getPath().value());
        log.info("请求方法:"+request.getMethod());
        log.info("请求参数:"+ request.getQueryParams());
        String sourceAddress = request.getLocalAddress().getHostString();
        log.info("请求来源地址:"+sourceAddress);
        log.info("请求来源地址:"+ request.getRemoteAddress());
        ServerHttpResponse response = exchange.getResponse();
        //3.(黑白名单)
        if(!IP_WHITE_LIST.contains(sourceAddress)){
            handleNoAuth(response);
        }
        //4.用户鉴权(判断 ak、sk 是否合法)
        // 从请求头中获取参数
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String nonce = headers.getFirst("nonce");
        String timestamp = headers.getFirst("timestamp");
        String sign = headers.getFirst("sign");
        String body = headers.getFirst("body");

// todo 实际情况应该是去数据库中查是否已分配给用户
        User invokeUser = null;
        try {
            invokeUser = innerUserService.getInvokeUser(accessKey);
        }catch (Exception e){
        log.error("getInvokeUser  ERROE",e);
        }
        if (invokeUser == null ||!invokeUser.getAccessKey().equals(accessKey)){
            return handleNoAuth(response);
        }
// 直接校验如果随机数大于1万，则抛出异常，并提示"无权限"
        if (Long.parseLong(nonce) > 10000) {
            return handleNoAuth(response);
        }
        Long currentTime = System.currentTimeMillis()/1000;
        final Long FIVE_MINUTES = 60 * 5L;
        //请求时间和当前时间不能超过五分钟
        if (currentTime - Long.parseLong(timestamp) >= FIVE_MINUTES) {
            return handleNoAuth(response);
        }


// todo 实际情况中是从数据库中查出 secretKey
        String serverSign = SignUtils.getSion(body, invokeUser.getSecretKey());
// 如果生成的签名不一致，则抛出异常，并提示"无权限"
        if (!sign.equals(serverSign)) {
            return handleNoAuth(response);
        }


        InterfaceInfo interfaceInfo = null;
        try {
            String path =   request.getPath().value();
            String method = request.getMethod().toString();
            interfaceInfo = innerInterfaceInfoService.getInterfaceInfo(path, method);

        }catch (Exception e){
            log.error("getInterfaceInfo  ERROE",e);
        }
        //接口不存在
        if(interfaceInfo == null){
            return handleNoAuth(response);//
        }else{
            interfaceInfo.setUrl( INTERFACE_HOST + request.getPath().value());
        }


// todo 调用次数 + 1


//        return handleNoAuth(response);
        //5.请求的模拟接口是杏存在?
        //6.请求转发，调用模拟接口
        return handleResponse(exchange, chain,interfaceInfo.getId(),invokeUser.getId());




    }

    @Override
    public int getOrder() {
        return -1;
    }

    /**
     * 无权限处理返回403状态码
     * @param response
     * @return
     */
    public Mono<Void> handleNoAuth(ServerHttpResponse response){
        //这个 Mono 其实是响应式编程的一种对象，类似于前端的 Promise。如果你款悉前端的异步操作，
        // 那么可以将 Mono 理解为类似的概念。在这段代码中，
        // 我们直接返回了这个 Mono，它并不包含响应参数。相当于我们告诉程序，请求处理完成了，不需要再执行其他操作了。
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    /**
     * 调用失败处理返回500状态码
     * @param response
     * @return
     */
    public Mono<Void> handleInvokeError(ServerHttpResponse response){
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }


    /**
     * 处理响应
     *
     * @param exchange
     * @param chain
     * @return
     */
    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain,long interfaceInfoId,long uerId) {
        try {
            // 获取原始的响应对象
            ServerHttpResponse originalResponse = exchange.getResponse();
            // 获取数据缓冲工厂
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();
            // 获取响应的状态码
            HttpStatus statusCode = originalResponse.getStatusCode();

            // 判断状态码是否为200 OK(按道理来说,现在没有调用,是拿不到响应码的,对这个保持怀疑 沉思.jpg)
            if(statusCode == HttpStatus.OK) {
                // 创建一个装饰后的响应对象(开始穿装备，增强能力)
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {

                    // 重写writeWith方法，用于处理响应体的数据
                    // 这段方法就是只要当我们的模拟接口调用完成之后,等它返回结果，
                    // 就会调用writeWith方法,我们就能根据响应结果做一些自己的处理
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        log.info("body instanceof Flux: {}", (body instanceof Flux));

                        // 判断响应体是否是Flux类型
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            // 返回一个处理后的响应体
                            // (这里就理解为它在拼接字符串,它把缓冲区的数据取出来，一点一点拼接好)
                            //8.调用成功，接口调用次数+1
                            if(originalResponse.getStatusCode() == HttpStatus.OK){  //调用过程中无异常
                                try {
                                    innerUserInterfaceInfoService.invokeCount(interfaceInfoId,uerId);
                                }catch (Exception e){
                                    log.error("invokeCount  ERROE",e);
                                }

                                System.out.println("调用成功，接口调用次数+1");
                            }else{
                                System.out.println("调用失败");
                                log.error("<--- {} 响应code异常", getStatusCode()); //记录异常日志

                            }
//                            AtomicReference<String> responseData = new AtomicReference<>();
                            Mono<Void> voidMono = super.writeWith(
                                    fluxBody.map(dataBuffer -> {
                                        // 读取响应体的内容并转换为字节数组
                                        byte[] content = new byte[dataBuffer.readableByteCount()];
                                        dataBuffer.read(content);
                                        DataBufferUtils.release(dataBuffer);//释放掉内存
                                        // 构建日志
                                        StringBuilder sb2 = new StringBuilder(200);
                                        List<Object> rspArgs = new ArrayList<>();
                                        rspArgs.add(originalResponse.getStatusCode());
                                        String data = new String(content, StandardCharsets.UTF_8);//data
                                        sb2.append(data);
                                        //7.响应日志
//                                        responseData.set(data);
                                        log.info("响应:" + data);
                                        // 将处理后的内容重新包装成DataBuffer并返回

                                        return bufferFactory.wrap(content);
                                    }));
//                            log.info(responseData.get());
                            return voidMono;

                        } else {
                            //9.调用失败，返回一个规范的错误码

                            log.error("<--- {} 响应code异常", getStatusCode()); //记录异常日志
                        }
                        return super.writeWith(body);
                    }
                };
                // 对于200 OK的请求,将装饰后的响应对象传递给下一个过滤器链,并继续处理(设置repsonse对象为装饰过的)

                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            // 对于非200 OK的请求，直接返回，进行降级处理
//            exchange.getResponse().setStatusCode(HttpStatus.BAD_GATEWAY);
            return chain.filter(exchange);
        }catch (Exception e){
            // 处理异常情况，记录错误日志
            log.error("网关处理响应异常" + e);
            return chain.filter(exchange);
        }
    }

}


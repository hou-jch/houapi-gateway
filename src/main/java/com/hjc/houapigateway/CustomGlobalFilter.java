package com.hjc.houapigateway;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import com.hjc.hjjcclientsdk.util.*;
import java.util.Arrays;
import java.util.List;

import static com.hjc.hjjcclientsdk.util.SignUtils.*;


/**
 * File Description: CustomGlobalFilter
 * 全局过滤方法
 * Author: hou-jch
 * Date: 2024/9/16
 */
@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {

    private static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");
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
        if (!"yupi".equals(accessKey)){
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
        String serverSign = getSion(body, "abcdefgh");
// 如果生成的签名不一致，则抛出异常，并提示"无权限"
        if (!sign.equals(serverSign)) {
            return handleNoAuth(response);
        }
// todo 调用次数 + 1


        //5.请求的模拟接口是杏存在?
        //6.请求转发，调用模拟接口
        Mono<Void> filter = chain.filter(exchange);

        //7.响应日志
        log.info("响应:" + response.getStatusCode());
        //8.调用成功，接口调用次数+1
        if(response.getStatusCode() == HttpStatus.OK){

        }else{
            return handleInvokeError(response);
        }
        //9.调用失败，返回一个规范的错误码


        return filter;
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
}


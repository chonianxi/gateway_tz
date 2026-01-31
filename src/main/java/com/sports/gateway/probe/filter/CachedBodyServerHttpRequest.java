package com.sports.gateway.probe.filter;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import reactor.core.publisher.Flux;

public class CachedBodyServerHttpRequest extends ServerHttpRequestDecorator {

    private final Flux<DataBuffer> body;

    public CachedBodyServerHttpRequest(ServerHttpRequest delegate, Flux<DataBuffer> body) {
        super(delegate);
        this.body = body;
    }

    @Override
    public Flux<DataBuffer> getBody() {
        return this.body;
    }
}

package com.trp.learningapp.api.gateway.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class AuthorizatinFilter extends BasicAuthenticationFilter {

	Environment env;

	public AuthorizatinFilter(AuthenticationManager authenticationManager, Environment env) {
		super(authenticationManager);
		this.env = env;
		// TODO Auto-generated constructor stub
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// TODO Auto-generated method stub
		String authorizationHeader = request.getHeader(env.getProperty("authorization.token.header.name"));
		if (authorizationHeader == null
				|| !authorizationHeader.startsWith(env.getProperty("authorization.token.header.prefix"))) {
			chain.doFilter(request, response);
			return;
		}

		UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		super.doFilterInternal(request, response, chain);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String authorizationHeader = request.getHeader(env.getProperty("authorization.token.header.name"));
		String token = authorizationHeader.replace(env.getProperty("authorization.token.header.prefix"), "");
		String userId = Jwts.parser().setSigningKey(env.getProperty("token.secret")).parseClaimsJws(token).getBody()
				.getSubject();

		if (userId == null) {
			return null;
		}
		return new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
	}
}

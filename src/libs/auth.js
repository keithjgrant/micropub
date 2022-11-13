
import got from 'got'

import { Error } from './response'

const Auth = {
	validateToken: async (tokenEndpoint, token) => {
		try {
			const { body } = await got(tokenEndpoint, {
				headers: {
					'accept': 'application/json',
					'Authorization': `Bearer ${token}`
				},
				responseType: 'json'
			})
			return body
		} catch (err) {
			console.error(err)
		}
	},
	isValidScope: (scope, requiredScopes) => {
		const validScopes = scope.split(' ')
		// Checks if at least one of the values in `requiredScopes` is in `validScopes`
		return requiredScopes.split(' ').some(sc => validScopes.includes(sc))
	},
	getToken: (headers, body) => {
		if (headers && headers.authorization && headers.authorization.split(' ')[1] && body && body['access_token']) {
			return Error.INVALID
		}
		const token = (headers && headers.authorization && headers.authorization.split(' ')[1]) || (body && body['access_token'])
		return token || Error.UNAUTHORIZED
	},
	isAuthorized: async (headers, body) => {
		console.log('HEADERS:', headers)
		console.log('BODY:', JSON.stringify(body))
		const headerToken = headers.authorization ? headers.authorization.split(' ')[1] : null;
		const bodyToken = body['access_token'];
		console.log({
			headerToken,
			bodyToken
		})
		if (headerToken && bodyToken && headerToken !== bodyToken) {
			console.log('Error; invalid', headerToken !== bodyToken)
			return Error.INVALID
		}
		const token = Auth.getToken(headers, body)
		if (!token || token.error) {
			console.log('Error; unauthorized', token)
			return token || Error.UNAUTHORIZED
		}
		const auth = await Auth.validateToken(process.env.TOKEN_ENDPOINT, token)
		if (!auth || auth.me != process.env.ME) {
			console.log('Error; forbidden')
			return Error.FORBIDDEN
		}
		console.log('authorized: ', auth)
		return auth
	}
}

export default Auth


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
		const headerToken = headers && headers.authorization ? headers.authorization.split(' ')[1] : null;
		const bodyToken = body ? body['access_token'] : null;
		if (headerToken && bodyToken && headerToken !== bodyToken) {
			return Error.INVALID
		}
		const token = headerToken || bodyToken;
		return token || Error.UNAUTHORIZED
	},
	isAuthorized: async (headers, body) => {
		console.log('HEADERS:', headers)
		console.log('BODY:', JSON.stringify(body))
		const token = Auth.getToken(headers, body)
		if (!token || token.error) {
			console.log('Error; unauthorized', token)
			return token || Error.UNAUTHORIZED
		}
		const auth = await Auth.validateToken(process.env.TOKEN_ENDPOINT, token)
		if (!auth || auth.me != process.env.ME) {
			console.log('Error; forbidden', auth, process.env.ME)
			return Error.FORBIDDEN
		}
		console.log('authorized: ', auth)
		return auth
	}
}

export default Auth

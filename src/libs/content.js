
import matter from 'gray-matter'
import { utils } from './utils'

const renameProperties = {
	'name': 'title',
	'category': 'tags'
}

const ignoreProperties = [
	'content', 'photo'
]

const content = {
	output: (data, clientId) => {
		if (!data) {
			return null
		}

		let output = {}
		for (let [key, value] of Object.entries(data)) {
			if (!ignoreProperties.includes(key)) {
				output[renameProperties[key] || key] = value
			}
		}
		if (clientId) {
			output['client_id'] = clientId
		}

		return matter.stringify(data.content || '', output)
	},

	format: (data, clientId) => {
		if (!data) {
			return null
		}
		const date = new Date()
		if (!data.date) {
			data.date = date.toISOString()
		} else {
			data.updated = date.toISOString()
		}
		const type = content.getType(data) || ''
		let slugParts = []
		if (process.env.FILENAME_FULL_DATE) { // Jekyll post filenames must have YYYY-MM-DD in the filename
			slugParts.push(date.toISOString().substr(0, 10)) // or split('T')[0]
		}
		if (data.slug) {
			slugParts.push(utils.slugify(data.slug))
		} else if (data.name) {
			slugParts.push(utils.slugify(data.name))
		} else {
			slugParts.push(Math.round(date / 1000))
		}

		const slug = slugParts.join('-')
		const dir = (process.env.CONTENT_DIR || 'src').replace(/\/$/, '')
		const pathParts = [type];
		console.log(process.env);
		if (process.env.PATH_YEAR) {
			pathParts.push(date.getFullYear().toString());
		}
		if (process.env.PATH_MONTH) {
			pathParts.push((date.getMonth() + 1).toString());
		}
		if (process.env.PATH_DAY) {
			pathParts.push(date.getDate().toString());
		}
		const path = pathParts.join('/')
		const { access_token, ...sanitized } = data;

		return {
			'filename': `${dir}/${path}/${slug}.md`,
			'slug': `${path}/${slug}`,
			'formatted': content.output(data, clientId),
			'data': sanitized,
		}
	},

	getType: data => {
		if (!utils.objectHasKeys(data)) {
			return null
		}
		if (data['like-of']) {
			return 'likes'
		}
		if (data['bookmark-of']) {
			return 'bookmarks'
		}
		if (data['rsvp'] && data['in-reply-to']) {
			return 'rsvp'
		}
		if (data['name']) {
			return 'articles'
		}
		return 'notes'
	},

	mediaFilename: file => {
		if (file && file.filename) {
			let dir = (process.env.MEDIA_DIR || 'uploads').replace(/\/$/, '')
			return `${dir}/${Math.round(new Date() / 1000)}_${file.filename}`
		}
	}
}

export default content

import { KeyDef } from './Key'

export interface KeyEntry { key: Buffer, def: KeyDef }
export interface PublicEntry {public: true}
export type MaybeKeyEntry = KeyEntry | PublicEntry

export class KeyCache {
    readonly feeds = new Map<string, Map<String, MaybeKeyEntry> | RangeEntries>()

    set(feed: string, id: number | string, value: MaybeKeyEntry) {
        let entries = this.feeds.get(feed)
        if (typeof id === 'number') {
            if (!entries) {
                entries = new RangeEntries()
                this.feeds.set(feed, entries)
            } else if (!(entries instanceof RangeEntries)) {
                throw new Error(`Feed KeyCache ${feed} isn't configured to use ranges`)
            }
            entries.set(id, value)
        } else if (typeof id === 'string') {
            if (!entries) {
                entries = new Map<string, MaybeKeyEntry>()
                this.feeds.set(feed, entries)
            } else if (!(entries instanceof Map)) {
                throw new Error(`Feed KeyCache ${feed} isn't configured for string IDs`)
            }
            entries.set(id, value)
        } else {
            throw new Error('id has to be either a string or a number')
        }
    }

    get(feed: string, id: number | string): MaybeKeyEntry | null {
        const entries = this.feeds.get(feed)
        if (!entries) return null
        return <MaybeKeyEntry>entries.get(<string & number>id)
    }

    delete(feed: string, id?: string | number) {
        if (id === undefined || id === null) {
            return this.feeds.delete(feed)
        } else {
            const entries = this.feeds.get(feed)
            if (!entries) return

            entries.delete(<string & number>id)
            if (entries.size === 0) {
                this.feeds.delete(feed)
            }

        }
    }

}

class RangeEntries {
    readonly entries = new Array<{ index: number, value: MaybeKeyEntry }>()

    set(index: number, value: MaybeKeyEntry) {
        if (typeof index !== 'number') throw new Error('RangeEntries requires a number as index')
        if (this.entries.length === 0) return this.entries.push({ index, value })

        let i = this.entries.length
        while (i > 0 && this.entries[i-1].index >= index) i--

        if (i === this.entries.length) this.entries.push({index, value})
        else if (this.entries[i].index === index) this.entries[i].value = value
        else this.entries.splice(i, 0, { index, value })
    }

    get(searched: number): MaybeKeyEntry | null {
        const idx = this.findIndex(searched)
        if (idx !== null) return this.entries[idx].value
        else return null
    }

    delete(searched: number) {
        const idx = this.findIndex(searched)
        if (idx !== null) {
            this.entries.splice(idx, 1)
        }
    }

    get size() {
        return this.entries.length
    }

    findIndex(searched: number): number | null {
        if (typeof searched !== 'number') throw new Error('RangeEntries requires a number as search param')
        if (this.entries.length === 0) return null

        let zerodiff = this.entries[0].index - searched
        // first element is larger -> no element that is <= value
        if (zerodiff > 0) return null
        // often this is the case, so check this before starting the binary search
        if (zerodiff === 0) return 0

        // also often the case: last element
        zerodiff = this.entries[this.entries.length - 1].index - searched
        if (zerodiff <= 0) return this.entries.length - 1

        let left = 0
        let right = this.entries.length - 1
        let mid = Math.floor((right - left) / 2)

        // binary search
        while (right - left > 1) {
            const midIdx = this.entries[mid].index
            const diff = midIdx - searched
            if (diff < 0) {
                left = mid
                mid = Math.floor((right - left) / 2) + mid
            } else {
                if (diff === 0) {
                    return mid
                }
                right = mid
                mid = Math.floor((right - left) / 2)
            }
        }
        return left
    }
}

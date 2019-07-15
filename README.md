# natural-rights-recrypt

Recrypt primitives interface for natural-rights

## Usage

    import recryptApiToNaturalRights from 'natural-rights-recrypt'
    const Recrypt = require('@ironcorelabs/recrypt-node-binding')
    const RecryptApi = new Recrypt.Api256()
    const Primitives = recryptApiToNaturalRights(RecryptApi)

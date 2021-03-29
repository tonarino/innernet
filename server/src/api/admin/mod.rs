use warp::Filter;

use crate::Context;

pub mod association;
pub mod cidr;
pub mod peer;

pub fn routes(
    context: Context,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("admin").and(
        association::routes::all(context.clone())
            .or(cidr::routes::all(context.clone()))
            .or(peer::routes::all(context.clone())),
    )
}

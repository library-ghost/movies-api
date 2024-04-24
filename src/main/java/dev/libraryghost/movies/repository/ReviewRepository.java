package dev.libraryghost.movies.repository;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import dev.libraryghost.movies.models.Review;

@Repository
public interface ReviewRepository extends MongoRepository<Review, ObjectId> {

}

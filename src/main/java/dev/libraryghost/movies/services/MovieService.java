package dev.libraryghost.movies.services;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import dev.libraryghost.movies.models.Movie;
import dev.libraryghost.movies.repository.MovieRepository;

@Service
public class MovieService {
    @Autowired
    private MovieRepository movieRepository;
    public List<Movie> allMovies() {
        return movieRepository.findAll();
    }

    public Optional<Movie> singleMovie(String imdbId) {
        return movieRepository.findMovieByImdbId(imdbId);
    }
}

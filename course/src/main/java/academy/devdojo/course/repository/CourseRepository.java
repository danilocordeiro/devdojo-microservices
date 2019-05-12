package academy.devdojo.course.repository;

import academy.devdojo.course.model.Course;
import org.springframework.data.repository.PagingAndSortingRepository;


public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {
}

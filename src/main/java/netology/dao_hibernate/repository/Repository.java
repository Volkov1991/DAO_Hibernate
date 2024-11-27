package netology.dao_hibernate.repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import lombok.AllArgsConstructor;
import netology.dao_hibernate.entity.Person;
import netology.dao_hibernate.entity.PersonID;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

import java.util.Optional;

@org.springframework.stereotype.Repository
public interface Repository extends JpaRepository<Person, PersonID> {

    List<Person> findPersonByCityOfLiving(String city);

    List<Person> findPersonByPersonId_AgeBeforeOrderByPersonId_Age(Integer age);

    Optional<Person> findPersonByPersonId_NameAndPersonId_Surname(String name, String surname);
}

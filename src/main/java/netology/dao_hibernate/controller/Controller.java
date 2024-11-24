package netology.dao_hibernate.controller;

import lombok.AllArgsConstructor;
import netology.dao_hibernate.entity.Person;
import netology.dao_hibernate.repository.Repository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@AllArgsConstructor
@RestController
public class Controller {

    private final Repository repository;


    @GetMapping("/persons/by-city")
    protected List<Person> findPersonByCityOfLiving(@RequestParam (value = "city", required = false) String city) {
        return repository.findPersonByCityOfLiving(city);
    }
    @GetMapping("/persons/by-age")
    protected List<Person> findPersonByPersonId_AgeBeforeOrderByPersonId_Age(@RequestParam(value = "age", required = false) Integer age){
        return repository.findPersonByPersonId_AgeBeforeOrderByPersonId_Age(age);
    }

    @GetMapping("/persons/by-name&surname")
    protected Optional<Person> findPersonByPersonId_NameAndPersonId_Surname(@RequestParam(value = "name", required = false) String name,@RequestParam(value = "surname", required = false) String surname){
        return repository.findPersonByPersonId_NameAndPersonId_Surname(name, surname);
    }

}
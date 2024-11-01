using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductsController : ControllerBase // Изменить на ControllerBase
    {
        [Authorize]
        [HttpGet]
        public ActionResult<Products> GetProducts() // Изменить метод на GetProducts
        {
            var prods = new Products
            {
                ProductList = new List<Product>
                {
                    new Product { Name = "Desc", Price = "3" },
                    new Product { Name = "Table", Price = "4" }
                }
            };

            return Ok(prods); // Возвратить статус 200 с данными
        }
    }

    public class Product
    {
        public string Name { get; set; }
        public string Price { get; set; }
    }

    public class Products
    {
        public List<Product> ProductList { get; set; } = new List<Product>(); // Измените на свойство
    }
}